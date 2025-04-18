## Overview

Detect RDP connections in VPC Flow Logs. Remote Desktop Protocol (RDP) connections, while necessary for Windows administration, can be exploited for unauthorized access to resources, lateral movement within networks, or command and control activities. Monitoring RDP connections helps identify potentially suspicious remote access attempts, especially from unexpected sources or to sensitive assets, which could indicate compromise or policy violations within your AWS environment.

This detection monitors only accepted traffic on port 3389 (RDP).

**References**:
- [Port Forwarding to RDP Using AWS Systems Manager Session Manager](https://aws.amazon.com/blogs/aws/new-port-forwarding-using-aws-systems-manager-sessions-manager/)
- [Using Session Manager for Remote Access](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html)
