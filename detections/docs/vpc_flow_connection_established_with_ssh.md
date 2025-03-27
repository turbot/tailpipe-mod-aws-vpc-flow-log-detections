## Overview

Detect when a VPC network flow established an SSH connection. SSH connections, while commonly used for legitimate administrative purposes, can also be leveraged for unauthorized access to resources, lateral movement within networks, or command and control activities by attackers. Monitoring SSH connections helps identify potentially suspicious remote access patterns, especially from unexpected sources, to sensitive resources or across security boundaries within your AWS environment.

**References**:
- [Securely Connect to Linux Instances Running in a Private Amazon VPC](https://aws.amazon.com/blogs/security/securely-connect-to-linux-instances-running-in-a-private-amazon-vpc/)
- [Replacing SSH Access with AWS Systems Manager Session Manager](https://aws.amazon.com/blogs/mt/replacing-ssh-access-with-aws-systems-manager-session-manager/)
- [Detecting Unusual SSH Activity Through AWS CloudTrail and VPC Flow Logs](https://aws.amazon.com/blogs/security/how-to-detect-suspicious-activity-in-your-aws-account-by-using-cloudtrail/)
- [Monitoring for Unauthorized Access Using AWS GuardDuty](https://aws.amazon.com/blogs/security/how-to-use-amazon-guardduty-and-vpc-flow-logs-to-identify-suspicious-traffic/)
- [How to Remediate SSH Brute Force Attacks in AWS](https://aws.amazon.com/blogs/security/how-to-remediate-amazon-guardduty-security-findings-automatically/)