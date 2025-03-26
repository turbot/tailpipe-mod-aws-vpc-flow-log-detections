## Overview

Detect when a VPC network flow established an RDP connection. Remote Desktop Protocol (RDP) connections, while necessary for Windows administration, can be exploited for unauthorized access to resources, lateral movement within networks, or command and control activities. Monitoring RDP connections helps identify potentially suspicious remote access attempts, especially from unexpected sources or to sensitive assets, which could indicate compromise or policy violations within your AWS environment.

**References**:
- [Port Forwarding to RDP Using AWS Systems Manager Session Manager](https://aws.amazon.com/blogs/aws/new-port-forwarding-using-aws-system-manager-sessions-manager/)
- [Automating Security Responses to RDP Brute Force Attacks](https://aws.amazon.com/blogs/security/how-to-automatically-update-your-security-groups-for-amazon-cloudfront-and-aws-waf-by-using-aws-lambda/)
- [Detecting RDP Tunneling with VPC Flow Logs](https://aws.amazon.com/blogs/security/how-to-use-amazon-guardduty-and-vpc-flow-logs-to-identify-suspicious-traffic/)
- [Remediating Detected RDP Vulnerabilities with AWS Systems Manager](https://aws.amazon.com/blogs/security/how-to-remediate-amazon-guardduty-security-findings-automatically/)
- [Windows RDP Attacks on AWS EC2 Instance and Mitigation Recommendations](https://aws.amazon.com/blogs/security/how-to-visualize-amazon-guardduty-findings/)