/*
 * MariaDB Client for Java Copyright (c) 2012-2014 Monty Program Ab. Copyright (c) 2015-2017 MariaDB
 * Ab. This library is free software; you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version. This library is distributed in
 * the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details. You should have received a copy of the GNU Lesser General Public License along
 * with this library; if not, write to Monty Program Ab info@montyprogram.com. This particular
 * MariaDB Client for Java file is work derived from a Drizzle-JDBC. Drizzle-JDBC file which is
 * covered by subject to the following copyright and notice provisions: Copyright (c) 2009-2011,
 * Marcus Eriksson Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met: Redistributions of source code must
 * retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions
 * and the following disclaimer in the documentation and/or other materials provided with the
 * distribution. Neither the name of the driver nor the names of its contributors may not be used to
 * endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
 * WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.mariadb.jdbc.internal.failover.impl;

import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.mariadb.jdbc.HostAddress;
import org.mariadb.jdbc.UrlParser;
import org.mariadb.jdbc.internal.com.read.dao.Results;
import org.mariadb.jdbc.internal.failover.tools.SearchFilter;
import org.mariadb.jdbc.internal.protocol.AuroraProtocol;
import org.mariadb.jdbc.internal.protocol.Protocol;
import org.mariadb.jdbc.internal.util.dao.ReconnectDuringTransactionException;
import org.mariadb.jdbc.internal.util.pool.GlobalStateInfo;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

public class AuroraListener extends MastersSlavesListener {

   private static final Logger logger = Logger.getLogger(AuroraListener.class.getName());
   private final Pattern auroraDnsPattern =
      Pattern.compile("(.+)\\.(cluster-)?([a-zA-Z0-9]+\\.[a-zA-Z0-9\\-]+\\.rds\\.amazonaws\\.com)",
         Pattern.CASE_INSENSITIVE);
   private final HostAddress clusterHostAddress;
   private String clusterDnsSuffix = null;

   /**
    * Constructor for Aurora. This differ from standard failover because : - we don't know current
    * master, we must check that after initial connection - master can change after he has a
    * failover
    *
    * @param urlParser connection information
    * @param globalInfo server global variables information
    * @throws SQLException when connection string contain host with different cluster
    */
   public AuroraListener(UrlParser urlParser, final GlobalStateInfo globalInfo) throws SQLException {
      super(urlParser, globalInfo);
      this.masterProtocol = null;
      this.secondaryProtocol = null;
      this.clusterHostAddress = this.findClusterHostAddress(urlParser);
   }

   /**
    * Retrieves the cluster host address from the UrlParser instance.
    *
    * @param urlParser object that holds the connection information
    * @return cluster host address
    */
   private HostAddress findClusterHostAddress(UrlParser urlParser) throws SQLException {
      final List<HostAddress> hostAddresses = urlParser.getHostAddresses();
      Matcher matcher;
      for (final HostAddress hostAddress : hostAddresses) {
         matcher = this.auroraDnsPattern.matcher(hostAddress.host);
         if (matcher.find()) {

            if (this.clusterDnsSuffix != null) {
               // ensure there is only one cluster
               if (!this.clusterDnsSuffix.equalsIgnoreCase(matcher.group(3))) {
                  throw new SQLException("Connection string must contain only one aurora cluster. " +
                     "'" + hostAddress.host + "' doesn't correspond to DNS prefix '" +
                     this.clusterDnsSuffix + "'");
               }
            }
            else {
               this.clusterDnsSuffix = matcher.group(3);
            }

            if (matcher.group(2) != null && !matcher.group(2).isEmpty()) {
               // not just an instance entry-point, but cluster entrypoint.
               return hostAddress;
            }
         }
         else {
            matcher = this.resolveAndMatchHostAddress(hostAddress.host);
            if (matcher != null) {

               if (this.clusterDnsSuffix != null) {
                  // ensure there is only one cluster
                  if (!this.clusterDnsSuffix.equalsIgnoreCase(matcher.group(3))) {
                     throw new SQLException(
                        "Connection string must contain only one aurora cluster. " + "'" +
                           matcher.group(0) + "' doesn't correspond to DNS prefix '" +
                           this.clusterDnsSuffix + "'");
                  }
               }
               else {
                  this.clusterDnsSuffix = matcher.group(3);
               }

               if (matcher.group(2) != null && !matcher.group(2).isEmpty()) {
                  // not just an instance entry-point, but cluster entrypoint.
                  return hostAddress;
               }
            }
            else if (this.clusterDnsSuffix == null && hostAddress.host.indexOf(".") > -1) {
               this.clusterDnsSuffix = hostAddress.host.substring(hostAddress.host.indexOf(".") + 1);
            }
         }
      }
      return null;
   }

   private Matcher resolveAndMatchHostAddress(String host) throws SQLException {
      try {
         final Name name = new Name(host + '.');
         final Record question = Record.newRecord(name, Type.A, DClass.IN);
         final Message query = Message.newQuery(question);

         final Message response = Lookup.getDefaultResolver().send(query);
         final Record[] records = response.getSectionArray(Section.ANSWER);
         for (final Record record : records) {
            if (record instanceof CNAMERecord) {
               final CNAMERecord cname = (CNAMERecord)record;
               final Matcher matcher = this.auroraDnsPattern.matcher(cname.getTarget().toString());

               if (matcher.find()) return matcher;
            }
         }
      }
      catch (final IOException e) {
         throw new SQLException(e);
      }

      return null;
   }

   public HostAddress getClusterHostAddress() {
      return this.clusterHostAddress;
   }

   /**
    * Search a valid connection for failed one. A Node can be a master or a replica depending on the
    * cluster state. so search for each host until found all the failed connection. By default,
    * search for the host not down, and recheck the down one after if not found valid connections.
    *
    * @param initialSearchFilter initial search filter
    * @throws SQLException if a connection asked is not found
    */
   @Override
   public void reconnectFailedConnection(SearchFilter initialSearchFilter) throws SQLException {
      SearchFilter searchFilter = initialSearchFilter;
      if (!searchFilter.isInitialConnection() && (this.isExplicitClosed() ||
         (searchFilter.isFineIfFoundOnlyMaster() && !this.isMasterHostFail()) ||
         searchFilter.isFineIfFoundOnlySlave() && !this.isSecondaryHostFail()))
      {
         return;
      }

      if (!searchFilter.isFailoverLoop()) {
         try {
            this.checkWaitingConnection();
            if ((searchFilter.isFineIfFoundOnlyMaster() && !this.isMasterHostFail()) ||
               searchFilter.isFineIfFoundOnlySlave() && !this.isSecondaryHostFail())
            {
               return;
            }
         }
         catch (final ReconnectDuringTransactionException e) {
            // don't throw an exception for this specific exception
            return;
         }
      }

      this.currentConnectionAttempts.incrementAndGet();

      this.resetOldsBlackListHosts();

      // put the list in the following order
      // - random order not connected host and not blacklisted
      // - random blacklisted host
      // - connected host at end.
      final List<HostAddress> loopAddress =
         new LinkedList<HostAddress>(this.urlParser.getHostAddresses());
      loopAddress.removeAll(this.getBlacklistKeys());
      Collections.shuffle(loopAddress);
      final List<HostAddress> blacklistShuffle =
         new LinkedList<HostAddress>(this.getBlacklistKeys());
      blacklistShuffle.retainAll(this.urlParser.getHostAddresses());
      Collections.shuffle(blacklistShuffle);
      loopAddress.addAll(blacklistShuffle);

      // put connected at end
      if (this.masterProtocol != null && !this.isMasterHostFail()) {
         loopAddress.remove(this.masterProtocol.getHostAddress());
         loopAddress.add(this.masterProtocol.getHostAddress());
      }

      if (!this.isSecondaryHostFail() && this.secondaryProtocol != null) {
         loopAddress.remove(this.secondaryProtocol.getHostAddress());
         loopAddress.add(this.secondaryProtocol.getHostAddress());
      }

      if (this.urlParser.getHostAddresses().size() <= 1) {
         searchFilter = new SearchFilter(true, false);
      }
      if ((this.isMasterHostFail() || this.isSecondaryHostFail()) ||
         searchFilter.isInitialConnection())
      {
         // while permit to avoid case when succeeded creating a new Master connection
         // and ping master connection fail a few milliseconds after,
         // resulting a masterConnection not initialized.
         do {
            AuroraProtocol.loop(this, this.globalInfo, loopAddress, searchFilter);
            if (!searchFilter.isFailoverLoop()) {
               try {
                  this.checkWaitingConnection();
               }
               catch (final ReconnectDuringTransactionException e) {
                  // don't throw an exception for this specific exception
               }
            }
         } while (searchFilter.isInitialConnection() && !(this.masterProtocol != null ||
            (this.urlParser.getOptions().allowMasterDownConnection &&
               this.secondaryProtocol != null)));
      }

      // When reconnecting, search if replicas list has change since first initialisation
      if (this.getCurrentProtocol() != null && !this.getCurrentProtocol().isClosed()) {
         this.retrieveAllEndpointsAndSet(this.getCurrentProtocol());
      }

      if (searchFilter.isInitialConnection() && this.masterProtocol == null &&
         !this.currentReadOnlyAsked)
      {
         this.currentProtocol = this.secondaryProtocol;
         this.currentReadOnlyAsked = true;
      }
   }

   /**
    * Retrieves the information necessary to add a new endpoint. Calls the methods that retrieves
    * the instance identifiers and sets urlParser accordingly.
    *
    * @param protocol current protocol connected to
    * @throws SQLException if connection error occur
    */
   public void retrieveAllEndpointsAndSet(Protocol protocol) throws SQLException {
      // For a given cluster, same port for all endpoints and same end host address
      if (this.clusterDnsSuffix != null) {
         final List<String> endpoints = this.getCurrentEndpointIdentifiers(protocol);
         this.setUrlParserFromEndpoints(endpoints, protocol.getPort());
      }

   }

   /**
    * Retrieves all endpoints of a cluster from the appropriate database table.
    *
    * @param protocol current protocol connected to
    * @return instance endpoints of the cluster
    * @throws SQLException if connection error occur
    */
   private List<String> getCurrentEndpointIdentifiers(Protocol protocol) throws SQLException {
      final List<String> endpoints = new ArrayList<String>();
      try {
         this.proxy.lock.lock();
         try {
            // Deleted instance may remain in db for 24 hours so ignoring instances that have had no
            // change
            // for 3 minutes
            final Results results = new Results();
            protocol.executeQuery(false, results,
               "select server_id, session_id from information_schema.replica_host_status " +
                  "where last_update_timestamp > now() - INTERVAL 3 MINUTE");
            results.commandEnd();
            final ResultSet resultSet = results.getResultSet();

            while (resultSet.next()) {
               endpoints.add(resultSet.getString(1) + "." + this.clusterDnsSuffix);
            }

            // randomize order for distributed load-balancing
            Collections.shuffle(endpoints);

         }
         finally {
            this.proxy.lock.unlock();
         }
      }
      catch (final SQLException qe) {
         AuroraListener.logger.warning("SQL exception occurred: " + qe.getMessage());
         if (protocol.getProxy().hasToHandleFailover(qe)) {
            if (this.masterProtocol == null || this.masterProtocol.equals(protocol)) {
               this.setMasterHostFail();
            }
            else if (this.secondaryProtocol.equals(protocol)) {
               this.setSecondaryHostFail();
            }
            this.addToBlacklist(protocol.getHostAddress());
            this.reconnectFailedConnection(
               new SearchFilter(this.isMasterHostFail(), this.isSecondaryHostFail()));
         }
      }

      return endpoints;
   }

   /**
    * Sets urlParser accordingly to discovered hosts.
    *
    * @param endpoints instance identifiers
    * @param port port that is common to all endpoints
    */
   private void setUrlParserFromEndpoints(List<String> endpoints, int port) {
      final List<HostAddress> addresses = new ArrayList<HostAddress>();
      for (final String endpoint : endpoints) {
         final HostAddress newHostAddress = new HostAddress(endpoint, port, null);
         addresses.add(newHostAddress);
      }

      synchronized (this.urlParser) {
         this.urlParser.setHostAddresses(addresses);
      }
   }

   /**
    * Looks for the current master/writer instance via the secondary protocol if it is found within
    * 3 attempts. Should it not be able to connect, the host is blacklisted and null is returned.
    * Otherwise, it will open a new connection to the cluster endpoint and retrieve the data from
    * there.
    *
    * @param secondaryProtocol the current secondary protocol
    * @param loopAddress list of possible hosts
    * @return the probable master address or null if not found
    */
   public HostAddress searchByStartName(Protocol secondaryProtocol, List<HostAddress> loopAddress) {
      if (!this.isSecondaryHostFail()) {
         int checkWriterAttempts = 3;
         HostAddress currentWriter = null;

         do {
            try {
               currentWriter = this.searchForMasterHostAddress(secondaryProtocol, loopAddress);
            }
            catch (final SQLException qe) {
               if (this.proxy.hasToHandleFailover(qe) && this.setSecondaryHostFail()) {
                  this.addToBlacklist(secondaryProtocol.getHostAddress());
                  return null;
               }
            }
            checkWriterAttempts--;
         } while (currentWriter == null && checkWriterAttempts > 0);

         // Handling special case where no writer is found from secondaryProtocol
         if (currentWriter == null && this.getClusterHostAddress() != null) {
            final AuroraProtocol possibleMasterProtocol =
               AuroraProtocol.getNewProtocol(this.getProxy(), this.globalInfo, this.getUrlParser());
            possibleMasterProtocol.setHostAddress(this.getClusterHostAddress());
            try {
               possibleMasterProtocol.connect();
               possibleMasterProtocol.setMustBeMasterConnection(true);
               this.foundActiveMaster(possibleMasterProtocol);
            }
            catch (final SQLException qe) {
               if (this.proxy.hasToHandleFailover(qe)) {
                  this.addToBlacklist(possibleMasterProtocol.getHostAddress());
               }
            }
         }

         return currentWriter;
      }
      return null;
   }

   /**
    * Aurora replica doesn't have the master endpoint but the master instance name. since the end
    * point normally use the instance name like
    * "instance-name.some_unique_string.region.rds.amazonaws.com", if an endpoint start with this
    * instance name, it will be checked first. Otherwise, the endpoint ending string is extracted
    * and used since the writer was newly created.
    *
    * @param protocol current protocol
    * @param loopAddress list of possible hosts
    * @return the probable host address or null if no valid endpoint found
    * @throws SQLException if any connection error occur
    */
   private HostAddress searchForMasterHostAddress(Protocol protocol, List<HostAddress> loopAddress)
      throws SQLException
   {
      String masterHostName;
      this.proxy.lock.lock();
      try {
         final Results results = new Results();
         protocol.executeQuery(false, results,
            "select server_id from information_schema.replica_host_status " +
               "where session_id = 'MASTER_SESSION_ID' " +
               "and last_update_timestamp > now() - INTERVAL 3 MINUTE " +
               "ORDER BY last_update_timestamp DESC LIMIT 1");
         results.commandEnd();
         final ResultSet queryResult = results.getResultSet();

         if (!queryResult.isBeforeFirst()) {
            return null;
         }
         else {
            queryResult.next();
            masterHostName = queryResult.getString(1);
         }
      }
      finally {
         this.proxy.lock.unlock();
      }

      Matcher matcher;
      if (masterHostName != null) {
         for (final HostAddress hostAddress : loopAddress) {
            matcher = this.auroraDnsPattern.matcher(hostAddress.host);
            if (hostAddress.host.startsWith(masterHostName) && !matcher.find()) {
               return hostAddress;
            }
         }

         HostAddress masterHostAddress;
         if (this.clusterDnsSuffix == null && protocol.getHost().contains(".")) {
            this.clusterDnsSuffix =
               protocol.getHost().substring(protocol.getHost().indexOf(".") + 1);
         }
         else {
            return null;
         }

         masterHostAddress =
            new HostAddress(masterHostName + "." + this.clusterDnsSuffix, protocol.getPort(), null);
         loopAddress.add(masterHostAddress);
         this.urlParser.setHostAddresses(loopAddress);
         return masterHostAddress;
      }

      return null;
   }

   @Override
   public boolean checkMasterStatus(SearchFilter searchFilter) {
      if (!this.isMasterHostFail()) {
         try {
            if (this.masterProtocol != null && !this.masterProtocol.checkIfMaster()) {
               // master has been demote, is now secondary
               this.setMasterHostFail();
               if (this.isSecondaryHostFail()) {
                  this.foundActiveSecondary(this.masterProtocol);
               }
               return true;
            }
         }
         catch (final SQLException e) {
            try {
               this.masterProtocol.ping();
            }
            catch (final SQLException ee) {
               this.proxy.lock.lock();
               try {
                  this.masterProtocol.close();
               }
               finally {
                  this.proxy.lock.unlock();
               }
               if (this.setMasterHostFail()) {
                  this.addToBlacklist(this.masterProtocol.getHostAddress());
               }
            }
            return true;
         }
      }

      if (!this.isSecondaryHostFail()) {
         try {
            if (this.secondaryProtocol != null && this.secondaryProtocol.checkIfMaster()) {
               // secondary has been promoted to master
               this.setSecondaryHostFail();
               if (this.isMasterHostFail()) {
                  this.foundActiveMaster(this.secondaryProtocol);
               }
               return true;
            }
         }
         catch (final SQLException e) {
            try {
               this.secondaryProtocol.ping();
            }
            catch (final Exception ee) {
               this.proxy.lock.lock();
               try {
                  this.secondaryProtocol.close();
               }
               finally {
                  this.proxy.lock.unlock();
               }
               if (this.setSecondaryHostFail()) {
                  this.addToBlacklist(this.secondaryProtocol.getHostAddress());
               }
               return true;
            }
         }
      }

      return false;
   }

}
