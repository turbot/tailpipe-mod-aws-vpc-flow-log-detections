# Overview

This detection identifies potential port scanning attempts from external sources targeting your AWS infrastructure. Port scanning is a reconnaissance technique used by attackers to discover open ports and services on network hosts. When external entities attempt connections to multiple ports on the same destination within a short timeframe, it often indicates someone is mapping your network for vulnerabilities.

The detection analyzes VPC Flow Logs to identify patterns consistent with port scanning activities, such as a single source IP addressing multiple ports on the same destination. Monitoring for this activity helps organizations detect the early stages of an attack, where adversaries are gathering information before attempting exploitation.

**References**:

* [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
* [MITRE ATT&CK: Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
* [MITRE ATT&CK: Active Scanning](https://attack.mitre.org/techniques/T1595/)
* [AWS Security Best Practices](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html) 