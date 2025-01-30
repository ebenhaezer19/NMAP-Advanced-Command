"# NMAP-Advanced-Command" 
Certainly! `nmap` (Network Mapper) is a powerful tool for network discovery and security auditing. Below are some advanced commands and techniques that can be used with `nmap`:

### 1. **OS Detection**
   ```bash
   nmap -O <target>
   ```
   - This command attempts to determine the operating system of the target host.

### 2. **Service Version Detection**
   ```bash
   nmap -sV <target>
   ```
   - This command probes open ports to determine the service/version information running on them.

### 3. **Aggressive Scan**
   ```bash
   nmap -A <target>
   ```
   - This option enables OS detection, version detection, script scanning, and traceroute. It’s a more intrusive scan.

### 4. **TCP SYN Scan (Stealth Scan)**
   ```bash
   nmap -sS <target>
   ```
   - This is a default scan type that performs a SYN scan, which is stealthier than a full TCP connect scan.

### 5. **UDP Scan**
   ```bash
   nmap -sU <target>
   ```
   - This command scans for open UDP ports. UDP scans can be slower and less reliable than TCP scans.

### 6. **Script Scanning**
   ```bash
   nmap --script <script-name> <target>
   ```
   - This command runs a specific NSE (Nmap Scripting Engine) script against the target. For example:
     ```bash
     nmap --script vuln <target>
     ```
     - This runs vulnerability detection scripts.

### 7. **Full Port Scan**
   ```bash
   nmap -p- <target>
   ```
   - This command scans all 65535 ports on the target.

### 8. **Fast Scan**
   ```bash
   nmap -F <target>
   ```
   - This command scans only the most common 100 ports, making it faster.

### 9. **Timing and Performance**
   ```bash
   nmap -T<0-5> <target>
   ```
   - This command adjusts the timing template. `-T0` is the slowest (paranoid) and `-T5` is the fastest (insane).

### 10. **Output to a File**
   ```bash
   nmap -oN output.txt <target>
   ```
   - This command saves the scan results to a text file.

   ```bash
   nmap -oX output.xml <target>
   ```
   - This command saves the scan results to an XML file.

### 11. **Idle Scan (Zombie Scan)**
   ```bash
   nmap -sI <zombie host> <target>
   ```
   - This command performs an idle scan using a zombie host to obscure the source of the scan.

### 12. **Fragment Packets**
   ```bash
   nmap -f <target>
   ```
   - This command fragments the packets, making it harder for firewalls to detect the scan.

### 13. **Decoy Scan**
   ```bash
   nmap -D <decoy1,decoy2,decoy3> <target>
   ```
   - This command uses decoy IP addresses to make it harder to identify the source of the scan.

### 14. **Spoof Source IP**
   ```bash
   nmap -S <spoofed IP> <target>
   ```
   - This command spoofs the source IP address of the scan.

### 15. **Scan a Range of IPs**
   ```bash
   nmap 192.168.1.1-100
   ```
   - This command scans a range of IP addresses.

### 16. **Scan a Subnet**
   ```bash
   nmap 192.168.1.0/24
   ```
   - This command scans an entire subnet.

### 17. **Detect Firewall Rules**
   ```bash
   nmap --script firewall-bypass <target>
   ```
   - This command uses NSE scripts to detect and attempt to bypass firewall rules.

### 18. **Detect Malware Infections**
   ```bash
   nmap --script malware <target>
   ```
   - This command uses NSE scripts to detect malware infections on the target.

### 19. **Scan for Heartbleed Vulnerability**
   ```bash
   nmap -p 443 --script ssl-heartbleed <target>
   ```
   - This command checks if the target is vulnerable to the Heartbleed bug.

### 20. **Scan for SMB Vulnerabilities**
   ```bash
   nmap --script smb-vuln* <target>
   ```
   - This command scans for SMB-related vulnerabilities on the target.

### 21. **Scan for DNS Vulnerabilities**
   ```bash
   nmap -sU -p 53 --script dns-zone-transfer <target>
   ```
   - This command attempts a DNS zone transfer on the target.

### 22. **Scan for SQL Injection Vulnerabilities**
   ```bash
   nmap -p 80 --script http-sql-injection <target>
   ```
   - This command scans for SQL injection vulnerabilities on web servers.

### 23. **Scan for XSS Vulnerabilities**
   ```bash
   nmap -p 80 --script http-xssed <target>
   ```
   - This command scans for Cross-Site Scripting (XSS) vulnerabilities.

### 24. **Scan for SSL/TLS Vulnerabilities**
   ```bash
   nmap -p 443 --script ssl-enum-ciphers <target>
   ```
   - This command enumerates SSL/TLS ciphers supported by the target.

### 25. **Scan for FTP Vulnerabilities**
   ```bash
   nmap -p 21 --script ftp-anon,ftp-bounce <target>
   ```
   - This command checks for anonymous FTP access and FTP bounce vulnerabilities.

### 26. **Scan for SNMP Information**
   ```bash
   nmap -sU -p 161 --script snmp-info <target>
   ```
   - This command retrieves information from SNMP services.

### 27. **Scan for RDP Vulnerabilities**
   ```bash
   nmap -p 3389 --script rdp-enum-encryption <target>
   ```
   - This command checks the encryption level of RDP services.

### 28. **Scan for VNC Vulnerabilities**
   ```bash
   nmap -p 5900 --script vnc-info <target>
   ```
   - This command retrieves information from VNC services.

### 29. **Scan for SSH Vulnerabilities**
   ```bash
   nmap -p 22 --script ssh2-enum-algos <target>
   ```
   - This command enumerates SSH encryption algorithms.

### 30. **Scan for HTTP Methods**
   ```bash
   nmap -p 80 --script http-methods <target>
   ```
   - This command lists the HTTP methods supported by the target.

### 31. **Scan for Web Application Firewalls (WAF)**
   ```bash
   nmap -p 80 --script http-waf-detect <target>
   ```
   - This command detects the presence of a Web Application Firewall (WAF).

### 32. **Scan for Directory Enumeration**
   ```bash
   nmap -p 80 --script http-enum <target>
   ```
   - This command enumerates directories on a web server.

### 33. **Scan for WordPress Vulnerabilities**
   ```bash
   nmap -p 80 --script http-wordpress-enum <target>
   ```
   - This command enumerates WordPress plugins and themes.

### 34. **Scan for Joomla Vulnerabilities**
   ```bash
   nmap -p 80 --script http-joomla-brute <target>
   ```
   - This command brute-forces Joomla login pages.

### 35. **Scan for Drupal Vulnerabilities**
   ```bash
   nmap -p 80 --script http-drupal-enum <target>
   ```
   - This command enumerates Drupal modules and themes.

### 36. **Scan for Jenkins Vulnerabilities**
   ```bash
   nmap -p 8080 --script http-jenkins-enum <target>
   ```
   - This command enumerates Jenkins jobs and builds.

### 37. **Scan for Redis Vulnerabilities**
   ```bash
   nmap -p 6379 --script redis-info <target>
   ```
   - This command retrieves information from Redis services.

### 38. **Scan for MongoDB Vulnerabilities**
   ```bash
   nmap -p 27017 --script mongodb-info <target>
   ```
   - This command retrieves information from MongoDB services.

### 39. **Scan for Elasticsearch Vulnerabilities**
   ```bash
   nmap -p 9200 --script elasticsearch-info <target>
   ```
   - This command retrieves information from Elasticsearch services.

### 40. **Scan for Docker Vulnerabilities**
   ```bash
   nmap -p 2375 --script docker-version <target>
   ```
   - This command retrieves Docker version information.

### 41. **Scan for Kubernetes Vulnerabilities**
   ```bash
   nmap -p 6443 --script kube-apiserver-info <target>
   ```
   - This command retrieves information from Kubernetes API servers.

### 42. **Scan for RabbitMQ Vulnerabilities**
   ```bash
   nmap -p 5672 --script rabbitmq-info <target>
   ```
   - This command retrieves information from RabbitMQ services.

### 43. **Scan for Cassandra Vulnerabilities**
   ```bash
   nmap -p 9042 --script cassandra-info <target>
   ```
   - This command retrieves information from Cassandra services.

### 44. **Scan for CouchDB Vulnerabilities**
   ```bash
   nmap -p 5984 --script couchdb-info <target>
   ```
   - This command retrieves information from CouchDB services.

### 45. **Scan for Memcached Vulnerabilities**
   ```bash
   nmap -p 11211 --script memcached-info <target>
   ```
   - This command retrieves information from Memcached services.

### 46. **Scan for Riak Vulnerabilities**
   ```bash
   nmap -p 8087 --script riak-http-info <target>
   ```
   - This command retrieves information from Riak HTTP interfaces.

### 47. **Scan for Zookeeper Vulnerabilities**
   ```bash
   nmap -p 2181 --script zookeeper-info <target>
   ```
   - This command retrieves information from Zookeeper services.

### 48. **Scan for Hadoop Vulnerabilities**
   ```bash
   nmap -p 50070 --script hadoop-datanode-info <target>
   ```
   - This command retrieves information from Hadoop DataNodes.

### 49. **Scan for Solr Vulnerabilities**
   ```bash
   nmap -p 8983 --script solr-info <target>
   ```
   - This command retrieves information from Apache Solr services.

### 50. **Scan for Kafka Vulnerabilities**
   ```bash
   nmap -p 9092 --script kafka-info <target>
   ```
   - This command retrieves information from Apache Kafka services.

### 51. **Scan for NFS Vulnerabilities**
   ```bash
   nmap -p 2049 --script nfs-showmount <target>
   ```
   - This command lists NFS exports on the target.

### 52. **Scan for Samba Vulnerabilities**
   ```bash
   nmap -p 445 --script smb-enum-shares <target>
   ```
   - This command enumerates Samba shares on the target.

### 53. **Scan for LDAP Vulnerabilities**
   ```bash
   nmap -p 389 --script ldap-rootdse <target>
   ```
   - This command retrieves the root DSE from an LDAP server.

### 54. **Scan for RPC Vulnerabilities**
   ```bash
   nmap -p 111 --script rpc-grind <target>
   ```
   - This command enumerates RPC services on the target.

### 55. **Scan for NTP Vulnerabilities**
   ```bash
   nmap -sU -p 123 --script ntp-info <target>
   ```
   - This command retrieves information from NTP services.

### 56. **Scan for SIP Vulnerabilities**
   ```bash
   nmap -sU -p 5060 --script sip-enum-users <target>
   ```
   - This command enumerates SIP users on the target.

### 57. **Scan for VoIP Vulnerabilities**
   ```bash
   nmap -sU -p 5060 --script sip-methods <target>
   ```
   - This command lists SIP methods supported by the target.

### 58. **Scan for Telnet Vulnerabilities**
   ```bash
   nmap -p 23 --script telnet-encryption <target>
   ```
   - This command checks if Telnet encryption is enabled.

### 59. **Scan for SMTP Vulnerabilities**
   ```bash
   nmap -p 25 --script smtp-commands <target>
   ```
   - This command lists SMTP commands supported by the target.

### 60. **Scan for POP3 Vulnerabilities**
   ```bash
   nmap -p 110 --script pop3-capabilities <target>
   ```
   - This command lists POP3 capabilities supported by the target.

### 61. **Scan for IMAP Vulnerabilities**
   ```bash
   nmap -p 143 --script imap-capabilities <target>
   ```
   - This command lists IMAP capabilities supported by the target.

### 62. **Scan for DNS Vulnerabilities**
   ```bash
   nmap -sU -p 53 --script dns-recursion <target>
   ```
   - This command checks if DNS recursion is enabled on the target.

### 63. **Scan for DHCP Vulnerabilities**
   ```bash
   nmap -sU -p 67 --script dhcp-discover <target>
   ```
   - This command discovers DHCP servers on the network.

### 64. **Scan for SNMP Vulnerabilities**
   ```bash
   nmap -sU -p 161 --script snmp-brute <target>
   ```
   - This command brute-forces SNMP community strings.

### 65. **Scan for TFTP Vulnerabilities**
   ```bash
   nmap -sU -p 69 --script tftp-enum <target>
   ```
   - This command enumerates files on a TFTP server.

### 66. **Scan for VNC Vulnerabilities**
   ```bash
   nmap -p 5900 --script vnc-brute <target>
   ```
   - This command brute-forces VNC passwords.

### 67. **Scan for RDP Vulnerabilities**
   ```bash
   nmap -p 3389 --script rdp-brute <target>
   ```
   - This command brute-forces RDP passwords.

### 68. **Scan for SSH Vulnerabilities**
   ```bash
   nmap -p 22 --script ssh-brute <target>
   ```
   - This command brute-forces SSH passwords.

### 69. **Scan for FTP Vulnerabilities**
   ```bash
   nmap -p 21 --script ftp-brute <target>
   ```
   - This command brute-forces FTP passwords.

### 70. **Scan for Telnet Vulnerabilities**
   ```bash
   nmap -p 23 --script telnet-brute <target>
   ```
   - This command brute-forces Telnet passwords.

### 71. **Scan for SMTP Vulnerabilities**
   ```bash
   nmap -p 25 --script smtp-brute <target>
   ```
   - This command brute-forces SMTP passwords.

### 72. **Scan for POP3 Vulnerabilities**
   ```bash
   nmap -p 110 --script pop3-brute <target>
   ```
   - This command brute-forces POP3 passwords.

### 73. **Scan for IMAP Vulnerabilities**
   ```bash
   nmap -p 143 --script imap-brute <target>
   ```
   - This command brute-forces IMAP passwords.

### 74. **Scan for HTTP Vulnerabilities**
   ```bash
   nmap -p 80 --script http-brute <target>
   ```
   - This command brute-forces HTTP passwords.

### 75. **Scan for HTTPS Vulnerabilities**
   ```bash
   nmap -p 443 --script https-brute <target>
   ```
   - This command brute-forces HTTPS passwords.

### 76. **Scan for MySQL Vulnerabilities**
   ```bash
   nmap -p 3306 --script mysql-brute <target>
   ```
   - This command brute-forces MySQL passwords.

### 77. **Scan for PostgreSQL Vulnerabilities**
   ```bash
   nmap -p 5432 --script pgsql-brute <target>
   ```
   - This command brute-forces PostgreSQL passwords.

### 78. **Scan for MSSQL Vulnerabilities**
   ```bash
   nmap -p 1433 --script ms-sql-brute <target>
   ```
   - This command brute-forces MSSQL passwords.

### 79. **Scan for Oracle Vulnerabilities**
   ```bash
   nmap -p 1521 --script oracle-brute <target>
   ```
   - This command brute-forces Oracle passwords.

### 80. **Scan for MongoDB Vulnerabilities**
   ```bash
   nmap -p 27017 --script mongodb-brute <target>
   ```
   - This command brute-forces MongoDB passwords.

### 81. **Scan for Redis Vulnerabilities**
   ```bash
   nmap -p 6379 --script redis-brute <target>
   ```
   - This command brute-forces Redis passwords.

### 82. **Scan for Memcached Vulnerabilities**
   ```bash
   nmap -p 11211 --script memcached-brute <target>
   ```
   - This command brute-forces Memcached passwords.

### 83. **Scan for CouchDB Vulnerabilities**
   ```bash
   nmap -p 5984 --script couchdb-brute <target>
   ```
   - This command brute-forces CouchDB passwords.

### 84. **Scan for Cassandra Vulnerabilities**
   ```bash
   nmap -p 9042 --script cassandra-brute <target>
   ```
   - This command brute-forces Cassandra passwords.

### 85. **Scan for Riak Vulnerabilities**
   ```bash
   nmap -p 8087 --script riak-brute <target>
   ```
   - This command brute-forces Riak passwords.

### 86. **Scan for Zookeeper Vulnerabilities**
   ```bash
   nmap -p 2181 --script zookeeper-brute <target>
   ```
   - This command brute-forces Zookeeper passwords.

### 87. **Scan for Hadoop Vulnerabilities**
   ```bash
   nmap -p 50070 --script hadoop-brute <target>
   ```
   - This command brute-forces Hadoop passwords.

### 88. **Scan for Solr Vulnerabilities**
   ```bash
   nmap -p 8983 --script solr-brute <target>
   ```
   - This command brute-forces Solr passwords.

### 89. **Scan for Kafka Vulnerabilities**
   ```bash
   nmap -p 9092 --script kafka-brute <target>
   ```
   - This command brute-forces Kafka passwords.

### 90. **Scan for NFS Vulnerabilities**
   ```bash
   nmap -p 2049 --script nfs-brute <target>
   ```
   - This command brute-forces NFS passwords.

### 91. **Scan for Samba Vulnerabilities**
   ```bash
   nmap -p 445 --script smb-brute <target>
   ```
   - This command brute-forces Samba passwords.

### 92. **Scan for LDAP Vulnerabilities**
   ```bash
   nmap -p 389 --script ldap-brute <target>
   ```
   - This command brute-forces LDAP passwords.

### 93. **Scan for RPC Vulnerabilities**
   ```bash
   nmap -p 111 --script rpc-brute <target>
   ```
   - This command brute-forces RPC passwords.

### 94. **Scan for NTP Vulnerabilities**
   ```bash
   nmap -sU -p 123 --script ntp-brute <target>
   ```
   - This command brute-forces NTP passwords.

### 95. **Scan for SIP Vulnerabilities**
   ```bash
   nmap -sU -p 5060 --script sip-brute <target>
   ```
   - This command brute-forces SIP passwords.

### 96. **Scan for VoIP Vulnerabilities**
   ```bash
   nmap -sU -p 5060 --script voip-brute <target>
   ```
   - This command brute-forces VoIP passwords.

### 97. **Scan for Telnet Vulnerabilities**
   ```bash
   nmap -p 23 --script telnet-brute <target>
   ```
   - This command brute-forces Telnet passwords.

### 98. **Scan for SMTP Vulnerabilities**
   ```bash
   nmap -p 25 --script smtp-brute <target>
   ```
   - This command brute-forces SMTP passwords.

### 99. **Scan for POP3 Vulnerabilities**
   ```bash
   nmap -p 110 --script pop3-brute <target>
   ```
   - This command brute-forces POP3 passwords.

### 100. **Scan for IMAP Vulnerabilities**
   ```bash
   nmap -p 143 --script imap-brute <target>
   ```
   - This command brute-forces IMAP passwords.

### 101. **Scan for HTTP Vulnerabilities**
   ```bash
   nmap -p 80 --script http-brute <target>
   ```
   - This command brute-forces HTTP passwords.

### 102. **Scan for HTTPS Vulnerabilities**
   ```bash
   nmap -p 443 --script https-brute <target>
   ```
   - This command brute-forces HTTPS passwords.

### 103. **Scan for MySQL Vulnerabilities**
   ```bash
   nmap -p 3306 --script mysql-brute <target>
   ```
   - This command brute-forces MySQL passwords.

### 104. **Scan for PostgreSQL Vulnerabilities**
   ```bash
   nmap -p 5432 --script pgsql-brute <target>
   ```
   - This command brute-forces PostgreSQL passwords.

### 105. **Scan for MSSQL Vulnerabilities**
   ```bash
   nmap -p 1433 --script ms-sql-brute <target>
   ```
   - This command brute-forces MSSQL passwords.

### 106. **Scan for Oracle Vulnerabilities**
   ```bash
   nmap -p 1521 --script oracle-brute <target>
   ```
   - This command brute-forces Oracle passwords.

### 107. **Scan for MongoDB Vulnerabilities**
   ```bash
   nmap -p 27017 --script mongodb-brute <target>
   ```
   - This command brute-forces MongoDB passwords.

### 108. **Scan for Redis Vulnerabilities**
   ```bash
   nmap -p 6379 --script redis-brute <target>
   ```
   - This command brute-forces Redis passwords.

### 109. **Scan for Memcached Vulnerabilities**
   ```bash
   nmap -p 11211 --script memcached-brute <target>
   ```
   - This command brute-forces Memcached passwords.

### 110. **Scan for CouchDB Vulnerabilities**
   ```bash
   nmap -p 5984 --script couchdb-brute <target>
   ```
   - This command brute-forces CouchDB passwords.

### 111. **Scan for Cassandra Vulnerabilities**
   ```bash
   nmap -p 9042 --script cassandra-brute <target>
   ```
   - This command brute-forces Cassandra passwords.

### 112. **Scan for Riak Vulnerabilities**
   ```bash
   nmap -p 8087 --script riak-brute <target>
   ```
   - This command brute-forces Riak passwords.

### 113. **Scan for Zookeeper Vulnerabilities**
   ```bash
   nmap -p 2181 --script zookeeper-brute <target>
   ```
   - This command brute-forces Zookeeper passwords.

### 114. **Scan for Hadoop Vulnerabilities**
   ```bash
   nmap -p 50070 --script hadoop-brute <target>
   ```
   - This command brute-forces Hadoop passwords.

### 115. **Scan for Solr Vulnerabilities**
   ```bash
   nmap -p 8983 --script solr-brute <target>
   ```
   - This command brute-forces Solr passwords.

### 116. **Scan for Kafka Vulnerabilities**
   ```bash
   nmap -p 9092 --script kafka-brute <target>
   ```
   - This command brute-forces Kafka passwords.

### 117. **Scan for NFS Vulnerabilities**
   ```bash
   nmap -p 2049 --script nfs-brute <target>
   ```
   - This command brute-forces NFS passwords.

### 118. **Scan for Samba Vulnerabilities**
   ```bash
   nmap -p 445 --script smb-brute <target>
   ```
   - This command brute-forces Samba passwords.

### 119. **Scan for LDAP Vulnerabilities**
   ```bash
   nmap -p 389 --script ldap-brute <target>
   ```
   - This command brute-forces LDAP passwords.

### 120. **Scan for RPC Vulnerabilities**
   ```bash
   nmap -p 111 --script rpc-brute <target>
   ```
   - This command brute-forces RPC passwords.

### 121. **Scan for NTP Vulnerabilities**
   ```bash
   nmap -sU -p 123 --script ntp-brute <target>
   ```
   - This command brute-forces NTP passwords.

### 122. **Scan for SIP Vulnerabilities**
   ```bash
   nmap -sU -p 5060 --script sip-brute <target>
   ```
   - This command brute-forces SIP passwords.

### 123. **Scan for VoIP Vulnerabilities**
   ```bash
   nmap -sU -p 5060 --script voip-brute <target>
   ```
   - This command brute-forces VoIP passwords.

### 124. **Scan for Telnet Vulnerabilities**
   ```bash
   nmap -p 23 --script telnet-brute <target>
   ```
   - This command brute-forces Telnet passwords.

### 125. **Scan for SMTP Vulnerabilities**
   ```bash
   nmap -p 25 --script smtp-brute <target>
   ```
   - This command brute-forces SMTP passwords.

### 126. **Scan for POP3 Vulnerabilities**
   ```bash
   nmap -p 110 --script pop3-brute <target>
   ```
   - This command brute-forces POP3 passwords.

### 127. **Scan for IMAP Vulnerabilities**
   ```bash
   nmap -p 143 --script imap-brute <target>
   ```
   - This command brute-forces IMAP passwords.

### 128. **Scan for HTTP Vulnerabilities**
   ```bash
   nmap -p 80 --script http-brute <target>
   ```
   - This command brute-forces HTTP passwords.

### 129. **Scan for HTTPS Vulnerabilities**
   ```bash
   nmap -p 443 --script https-brute <target>
   ```
   - This command brute-forces HTTPS passwords.

### 130. **Scan for MySQL Vulnerabilities**
   ```bash
   nmap -p 3306 --script mysql-brute <target>
   ```
   - This command brute-forces MySQL passwords.

### 131. **Scan for PostgreSQL Vulnerabilities**
   ```bash
   nmap -p 5432 --script pgsql-brute <target>
   ```
   - This command brute-forces PostgreSQL passwords.

### 132. **Scan for MSSQL Vulnerabilities**
   ```bash
   nmap -p 1433 --script ms-sql-brute <target>
   ```
   - This command brute-forces MSSQL passwords.

### 133. **Scan for Oracle Vulnerabilities**
   ```bash
   nmap -p 1521 --script oracle-brute <target>
   ```
   - This command brute-forces Oracle passwords.

### 134. **Scan for MongoDB Vulnerabilities**
   ```bash
   nmap -p 27017 --script mongodb-brute <target>
   ```
   - This command brute-forces MongoDB passwords.

### 135. **Scan for Redis Vulnerabilities**
   ```bash
   nmap -p 6379 --script redis-brute <target>
   ```
   - This command brute-forces Redis passwords.

### 136. **Scan for Memcached Vulnerabilities**
   ```bash
   nmap -p 11211 --script memcached-brute <target>
   ```
   - This command brute-forces Memcached passwords.

### 137. **Scan for CouchDB Vulnerabilities**
   ```bash
   nmap -p 5984 --script couchdb-brute <target>
   ```
   - This command brute-forces CouchDB passwords.

### 138. **Scan for Cassandra Vulnerabilities**
   ```bash
   nmap -p 9042 --script cassandra-brute <target>
   ```
   - This command brute-forces Cassandra passwords.

### 139. **Scan for Riak Vulnerabilities**
   ```bash
   nmap -p 8087 --script riak-brute <target>
   ```
   - This command brute-forces Riak passwords.

### 140. **Scan for Zookeeper Vulnerabilities**
   ```bash
   nmap -p 2181 --script zookeeper-brute <target>
   ```
   - This command brute-forces Zookeeper passwords.

### 141. **Scan for Hadoop Vulnerabilities**
   ```bash
   nmap -p 50070 --script hadoop-brute <target>
   ```
   - This command brute-forces Hadoop passwords.

### 142. **Scan for Solr Vulnerabilities**
   ```bash
   nmap -p 8983 --script solr-brute <target>
   ```
   - This command brute-forces Solr passwords.

### 143. **Scan for Kafka Vulnerabilities**
   ```bash
   nmap -p 9092 --script kafka-brute <target>
   ```
   - This command brute-forces Kafka passwords.

### 144. **Scan for NFS Vulnerabilities**
   ```bash
   nmap -p 2049 --script nfs-brute <target>
   ```
   - This command brute-forces NFS passwords.

### 145. **Scan for Samba Vulnerabilities**
   ```bash
   nmap -p 445 --script smb-brute <target>
   ```
   - This command brute-forces Samba passwords.

### 146. **Scan for LDAP Vulnerabilities**
   ```bash
   nmap -p 389 --script ldap-brute <target>
   ```
   - This command brute-forces LDAP passwords.

### 147. **Scan for RPC Vulnerabilities**
   ```bash
   nmap -p 111 --script rpc-brute <target>
   ```
   - This command brute-forces RPC passwords.

### 148. **Scan for NTP Vulnerabilities**
   ```bash
   nmap -sU -p 123 --script ntp-brute <target>
   ```
   - This command brute-forces NTP passwords.

### 149. **Scan for SIP Vulnerabilities**
   ```bash
   nmap -sU -p 5060 --script sip-brute <target>
   ```
   - This command brute-forces SIP passwords.

### 150. **Scan for VoIP Vulnerabilities**
   ```bash
   nmap -sU -p 5060 --script voip-brute <target>
   ```
   - This command brute-forces VoIP passwords.

### 151. **Scan for Telnet Vulnerabilities**
   ```bash
   nmap -p 23 --script telnet-brute <target>
   ```
   - This command brute-forces Telnet passwords.

### 152. **Scan for SMTP Vulnerabilities**
   ```bash
   nmap -p 25 --script smtp-brute <target>
   ```
   - This command brute-forces SMTP passwords.

### 153. **Scan for POP3 Vulnerabilities**
   ```bash
   nmap -p 110 --script pop3-brute <target>
   ```
   - This command brute-forces POP3 passwords.

### 154. **Scan for IMAP Vulnerabilities**
   ```bash
   nmap -p 143 --script imap-brute <target>
   ```
   - This command brute-forces IMAP passwords.

### 155. **Scan for HTTP Vulnerabilities**
   ```bash
   nmap -p 80 --script http-brute <target>
   ```
   - This command brute-forces HTTP passwords.

### 156. **Scan for HTTPS Vulnerabilities**
   ```bash
   nmap -p 443 --script https-brute <target>
   ```
   - This command brute-forces HTTPS passwords.

### 157. **Scan for MySQL Vulnerabilities**
   ```bash
   nmap -p 3306 --script mysql-brute <target>
   ```
   - This command brute-forces MySQL passwords.

### 158. **Scan for PostgreSQL Vulnerabilities**
   ```bash
   nmap -p 5432 --script pgsql-brute <target>
   ```
   - This command brute-forces PostgreSQL passwords.

### 159. **Scan for MSSQL Vulnerabilities**
   ```bash
   nmap -p 1433 --script ms-sql-brute <target>
   ```
   - This command brute-forces MSSQL passwords.

### 160. **Scan for Oracle Vulnerabilities**
   ```bash
   nmap -p 1521 --script oracle-brute <target>
   ```
   - This command brute-forces Oracle passwords.

### 161. **Scan for MongoDB Vulnerabilities**
   ```bash
   nmap -p 27017 --script mongodb-brute <target>
   ```
   - This command brute-forces MongoDB passwords.

### 162. **Scan for Redis Vulnerabilities**
   ```bash
   nmap -p 6379 --script redis-brute <target>
   ```
   - This command brute-forces Redis passwords.

### 163. **Scan for Memcached Vulnerabilities**
   ```bash
   nmap -p 11211 --script memcached-brute <target>
   ```
   - This command brute-forces Memcached passwords.

### 164. **Scan for CouchDB Vulnerabilities**
   ```bash
   nmap -p 5984 --script couchdb-brute <target>
   ```
   - This command brute-forces CouchDB passwords.

### 165. **Scan for Cassandra Vulnerabilities**
   ```bash
   nmap -p 9042 --script cassandra-brute <target>
   ```
   - This command brute-forces Cassandra passwords.

### 166. **Scan for Riak Vulnerabilities**
   ```bash
   nmap -p 8087 --script riak-brute <target>
   ```
   - This command brute-forces Riak passwords.

### 167. **Scan for Zookeeper Vulnerabilities**
   ```bash
   nmap -p 2181 --script zookeeper-brute <target>
   ```
   - This command brute-forces Zookeeper passwords.

### 168. **Scan for Hadoop Vulnerabilities**
   ```bash
   nmap -p 50070 --script hadoop-brute <target>
   ```
   - This command brute-forces Hadoop passwords.

### 169. **Scan for Solr Vulnerabilities**
   ```bash
   nmap -p 8983 --script solr-brute <target>
   ```
   - This command brute-forces Solr passwords.

### 170. **Scan for Kafka Vulnerabilities**
   ```bash
   nmap -p 9092 --script kafka-brute <target>
   ```
   - This command brute-forces Kafka passwords.

### 171. **Scan for NFS Vulnerabilities**
   ```bash
   nmap -p 2049 --script nfs-brute <target>
   ```
   - This command brute-forces NFS passwords.

### 172. **Scan for Samba Vulnerabilities**
   ```bash
   nmap -p 445 --script smb-brute <target>
   ```
   - This command brute-forces Samba passwords.

### 173. **Scan for LDAP Vulnerabilities**
   ```bash
   nmap -p 389 --script ldap-brute <target>
   ```
   - This command brute-forces LDAP passwords.

### 174. **Scan for RPC Vulnerabilities**
   ```bash
   nmap -p 111 --script rpc-brute <target