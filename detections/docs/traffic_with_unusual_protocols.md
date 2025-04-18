## Overview

Detect unusual protocol usage in VPC Flow Logs. Unusual protocol usage may indicate potential tunneling techniques, covert communication channels, or command and control traffic attempting to evade security controls. Monitoring for uncommon protocols helps identify adversaries using non-standard communication methods to maintain persistence, exfiltrate data, or control compromised systems while bypassing traditional detection mechanisms focused on common protocols.

This detection monitors only accepted traffic for protocols other than TCP (6), UDP (17), and ICMP (1).

**References**:
- [Protocol Numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
