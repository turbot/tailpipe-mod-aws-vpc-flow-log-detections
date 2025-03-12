# Overview

This detection identifies potential port scanning activity originating from within your AWS infrastructure. While external port scanning is a common threat, internal port scanning often indicates lateral movement attempts by an attacker who has already gained a foothold in your environment or potentially unauthorized activities by insiders. 

The detection analyzes VPC Flow Logs to identify instances where an internal source IP attempts connections to multiple ports on another internal host within a short timeframe. This pattern is consistent with reconnaissance techniques used to discover available services during lateral movement. Detecting internal port scanning is critical for identifying attackers who are attempting to expand their access within the network after an initial compromise.

**References**:

* [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
* [MITRE ATT&CK: Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
* [MITRE ATT&CK: Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
* [AWS Security Best Practices](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html)
* [Lateral Movement Detection](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html) 