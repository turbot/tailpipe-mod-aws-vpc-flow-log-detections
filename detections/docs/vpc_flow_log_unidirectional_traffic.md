# Overview

This detection identifies network flows with high volume in a single direction without corresponding return traffic, which may indicate data exfiltration or command and control activity. In normal network communications, traffic is typically bidirectional, with a balance between inbound and outbound data. A significant imbalance, particularly large outbound data transfer without proportional inbound traffic, could represent unauthorized data exfiltration.

The detection aggregates flow log data to identify source-destination pairs with substantial unidirectional traffic, helping security teams discover potential data theft, covert channels, or compromised systems that are sending data to external entities.

**References**:

* [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
* [MITRE ATT&CK: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
* [MITRE ATT&CK: Data Exfiltration](https://attack.mitre.org/tactics/TA0010/)
* [AWS Network Traffic Privacy](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/network-traffic-privacy.html) 