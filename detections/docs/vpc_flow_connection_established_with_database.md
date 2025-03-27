## Overview

Detect when a VPC network flow established a connection to database ports. Database connections from unexpected or unauthorized sources could indicate potential unauthorized access attempts, data exfiltration, or lateral movement activities within your cloud environment. Monitoring database access patterns helps identify suspicious connections that bypass application tiers, originate from unusual locations, or occur during abnormal time periods, which may signal compromise of database resources.

**References**:
- [Database Activity Monitoring with AWS Network Firewall](https://aws.amazon.com/blogs/security/monitoring-network-traffic-of-amazon-rds-and-amazon-redshift-with-network-firewall/)
- [Protecting Data with AWS CloudTrail and VPC Flow Logs](https://aws.amazon.com/blogs/database/auditing-for-your-amazon-rds-for-postgresql-and-amazon-aurora-postgresql-databases/)
- [Preventing Unauthorized Database Access with Network ACLs](https://aws.amazon.com/blogs/database/securing-amazon-rds-and-aurora-postgresql-database-access-with-ssl-tls/)
- [Detecting and Preventing Database Compromises with AWS Security Hub](https://aws.amazon.com/blogs/security/how-to-create-and-use-custom-aws-security-hub-insights/)
- [Database Connection Monitoring Using VPC Flow Logs and Amazon Athena](https://aws.amazon.com/blogs/big-data/analyzing-vpc-flow-logs-using-amazon-athena-to-uncover-database-traffic-patterns/)