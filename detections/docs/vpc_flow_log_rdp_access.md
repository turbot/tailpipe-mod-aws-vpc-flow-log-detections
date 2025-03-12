# Overview

Detect RDP connections to instances, which should be monitored for security purposes. Remote Desktop Protocol (RDP, port 3389) is commonly used for remote administration of Windows instances but represents a significant attack vector if exposed. Monitoring RDP access helps identify potentially unauthorized access attempts, brute force attacks, and ensures compliance with access control policies and security best practices.

**References**:

* [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
* [MITRE ATT&CK: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
* [AWS Security Best Practices for Windows](https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2-windows-best-practices.html)
* [Microsoft RDP Security Guidance](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/secure-the-remote-desktop-services-session/) 