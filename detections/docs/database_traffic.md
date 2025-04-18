## Overview

Detect database traffic in VPC Flow Logs. Database connections from unexpected or unauthorized sources could indicate potential unauthorized access attempts, data exfiltration, or lateral movement activities within your cloud environment. Monitoring database access patterns helps identify suspicious connections that bypass application tiers, originate from unusual locations, or occur during abnormal time periods, which may signal compromise of database resources.

This detection monitors only accepted traffic.

Monitored Ports:
- AWS Aurora: 1150
- Microsoft SQL Server: 1433, 1434
- Oracle: 1521, 1522, 1526
- MySQL/MariaDB: 3306, 3307
- PostgreSQL: 5432, 5433
- CouchDB: 5984
- Redis/ElastiCache: 6379-6383
- Cassandra/Keyspaces: 7000, 7001, 9042, 9160
- ArangoDB: 8529
- Memcached: 11211
- MongoDB/DocumentDB: 27017-27019

**References**:
- [AWS RDS Security Best Practices](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_BestPractices.Security.html)
