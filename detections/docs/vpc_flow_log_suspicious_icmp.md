# Overview

This detection identifies unusual or excessive ICMP (Internet Control Message Protocol) traffic patterns that may indicate reconnaissance, tunneling, or covert channel activities. While ICMP serves legitimate network management purposes, it can also be abused by attackers for network mapping, data exfiltration through ICMP tunneling, or maintaining covert command and control channels.

The detection analyzes VPC Flow Logs to identify ICMP traffic that exhibits suspicious characteristics, such as unusual volumes, persistent connections, or patterns that don't align with expected network management activities. Monitoring ICMP traffic is valuable for identifying potential reconnaissance activities like ping sweeps, as well as more sophisticated threats like ICMP tunneling, where the protocol is misused to carry unauthorized data or commands.

**References**:

* [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
* [MITRE ATT&CK: Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
* [MITRE ATT&CK: Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)
* [ICMP Tunneling Techniques](https://www.sans.org/reading-room/whitepapers/protocols/detecting-preventing-unauthorized-outbound-traffic-1951)
* [AWS Security Best Practices](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html) 