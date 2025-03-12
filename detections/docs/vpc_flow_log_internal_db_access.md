# Overview

This detection monitors for direct database access from unexpected or unauthorized internal sources, which could indicate lateral movement, data access abuse, or insider threats. In well-architected environments, database access should typically be restricted to application servers or designated administrative systems, with proper authentication and access controls in place.

The detection analyzes VPC Flow Logs to identify connections to database ports (such as 3306 for MySQL, 5432 for PostgreSQL, 1521 for Oracle, or 1433 for MS SQL) from internal sources that aren't on an allowlist of approved systems. Unauthorized database access can lead to data breaches, data manipulation, or data theft, making it critical to monitor for unusual access patterns that may indicate compromise or policy violations.

**References**:

* [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
* [MITRE ATT&CK: Data from Local System](https://attack.mitre.org/techniques/T1005/)
* [MITRE ATT&CK: Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
* [AWS Database Security Best Practices](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/database-compromises.html)
* [AWS RDS Security](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_Security.html) 