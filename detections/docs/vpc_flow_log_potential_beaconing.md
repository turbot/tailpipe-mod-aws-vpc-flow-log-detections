# Overview

This detection identifies regular, periodic network connections that may indicate command and control beaconing activity. Beaconing is a technique used by malware and other malicious software to establish and maintain communication with attacker-controlled servers. These communications typically follow regular patterns, with connections occurring at consistent intervals.

The detection analyzes VPC Flow Logs to identify regular communication patterns between internal and external systems, focusing on connections that occur with consistent timing and similar packet sizes. Identifying beaconing activity is crucial for detecting compromised systems that are awaiting instructions, exfiltrating data, or maintaining persistent access for attackers.

**References**:

* [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
* [MITRE ATT&CK: Command and Control](https://attack.mitre.org/tactics/TA0011/)
* [MITRE ATT&CK: Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
* [MITRE ATT&CK: Encrypted Channel](https://attack.mitre.org/techniques/T1573/)
* [AWS Network Monitoring Best Practices](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/network-monitoring.html) 