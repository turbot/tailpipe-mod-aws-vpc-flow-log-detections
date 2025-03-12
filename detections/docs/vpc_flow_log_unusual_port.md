# Overview

This detection identifies network traffic over uncommon or suspicious ports that may indicate malicious activity. Attackers often use non-standard ports for command and control communications, data exfiltration, or to evade security controls. By monitoring connections to unusual ports (e.g., port 4444 commonly used by Metasploit), security teams can identify potential compromise, malware communication channels, or policy violations.

The detection focuses on known suspicious ports that are frequently associated with malicious tools, backdoors, or trojan activity, helping organizations identify threats that might otherwise go unnoticed in normal network traffic.

**References**:

* [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
* [MITRE ATT&CK: Non-Standard Port](https://attack.mitre.org/techniques/T1571/)
* [MITRE ATT&CK: Command and Control](https://attack.mitre.org/tactics/TA0011/)
* [Common Ports Used in Cyber Attacks](https://www.mandiant.com/resources/blog/scanning-the-internet) 