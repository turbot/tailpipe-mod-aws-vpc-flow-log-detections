# Overview

This detection identifies potential data exfiltration via DNS tunneling by monitoring for abnormal DNS traffic patterns. DNS tunneling is a technique used by attackers to bypass security controls by encapsulating non-DNS traffic within DNS queries and responses. This method can be used to maintain command and control communications or exfiltrate data from compromised systems while evading detection.

The detection analyzes VPC Flow Logs to identify unusually high volumes of DNS traffic (port 53) between internal hosts and external DNS servers, which may indicate DNS tunneling activity. Characteristics monitored include excessive query volumes, abnormal data sizes, or persistent connections to unusual DNS servers. Identifying DNS-based exfiltration is important for preventing data theft that might otherwise remain undetected by traditional security controls.

**References**:

* [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
* [MITRE ATT&CK: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
* [MITRE ATT&CK: DNS](https://attack.mitre.org/techniques/T1071/004/)
* [SANS: Detecting DNS Tunneling](https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152)
* [AWS Route 53 Security](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/security.html) 