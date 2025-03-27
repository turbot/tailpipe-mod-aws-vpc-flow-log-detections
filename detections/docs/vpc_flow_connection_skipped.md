## Overview

Detect when VPC Flow Logs were skipped during the aggregation interval. Skipped flow logs create gaps in network visibility that could potentially mask malicious network activity, hinder incident investigations, or lead to compliance violations. These gaps may occur due to throttling, performance issues, or intentional tampering with logging configurations. Continuous monitoring of network traffic is essential for maintaining a strong security posture and ensuring comprehensive audit trails.

**References**:
- [Resolving VPC Flow Log Delivery Issues](https://aws.amazon.com/premiumsupport/knowledge-center/vpc-flow-logs-s3-cloudwatch/)
- [Logging and Monitoring Best Practices for Security Incident Response](https://aws.amazon.com/blogs/security/logging-and-monitoring-best-practices-for-security-incident-response/)
- [Detecting Gaps in Logging and Monitoring](https://aws.amazon.com/blogs/security/how-to-audit-your-aws-environment-for-security-best-practices/)
- [Defending Against Disruption of Telemetry](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/security-capabilities.html)
- [Using VPC Flow Logs for SIEM Correlation](https://aws.amazon.com/blogs/security/how-to-get-started-with-security-information-and-event-management-using-amazon-elasticsearch-service/)