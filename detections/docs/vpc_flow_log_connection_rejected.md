# Overview

This detection monitors rejected network connections in VPC Flow Logs to identify denied access attempts and potential security threats. Rejected connections occur when traffic is blocked by security groups, network ACLs, or other network security controls. A high volume of rejected connections may indicate scanning activity, brute force attempts, or misconfigured applications.

By analyzing patterns of rejected connections, security teams can identify potential threats that are being blocked by existing security measures, review the effectiveness of security configurations, and detect misconfigured applications that are generating unnecessary connection attempts. This detection is valuable for understanding the nature of blocked traffic and identifying changes in threat patterns against your AWS infrastructure.

**References**:

* [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
* [Security Group Rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
* [Network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)
* [AWS Security Best Practices](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html) 