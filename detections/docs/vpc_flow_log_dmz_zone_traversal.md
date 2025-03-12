# Overview

This detection identifies traffic that bypasses the DMZ (Demilitarized Zone) in your AWS environment, potentially indicating security control bypass or lateral movement. In a properly configured network architecture, external traffic should only access internal resources through designated DMZ or intermediary systems, such as load balancers, web application firewalls, or proxy servers.

The detection analyzes VPC Flow Logs to identify instances where direct connections occur between external sources and internal systems, bypassing expected DMZ intermediaries. This pattern could indicate misconfigured security groups or network ACLs, compromised systems, or deliberate attempts to circumvent security controls. Monitoring DMZ traversal patterns helps maintain proper network segmentation and identifies potential security architecture weaknesses.

**References**:

* [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
* [MITRE ATT&CK: Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
* [AWS Security Best Practices](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
* [VPC Network Security](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security.html)
* [AWS Network Segmentation Patterns](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/networking.html) 