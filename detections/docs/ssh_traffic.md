## Overview

Detect SSH connections in VPC Flow Logs. SSH connections, while commonly used for legitimate administrative purposes, can also be leveraged for unauthorized access to resources, lateral movement within networks, or command and control activities by attackers. Monitoring SSH connections helps identify potentially suspicious remote access patterns, especially from unexpected sources, to sensitive resources or across security boundaries within your AWS environment.

This detection monitors only accepted traffic on port 22 (SSH).

**References**:
- [Securely Connect to Linux Instances Running in a Private Amazon VPC](https://aws.amazon.com/blogs/security/securely-connect-to-linux-instances-running-in-a-private-amazon-vpc/)
- [Security Best Practices for Linux on AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html)
- [AWS Systems Manager Session Manager for SSH Access](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-sessions-start.html#sessions-start-ssh)
