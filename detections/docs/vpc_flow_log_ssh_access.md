# Overview

This detection monitors SSH connections to AWS instances, identifying potential unauthorized access attempts and administrative activity. SSH (port 22) is commonly used for remote system management but can also be a vector for attacks if not properly secured. By tracking SSH connections, organizations can validate administrative access patterns, detect potential brute force attacks, and identify policy violations.

The detection focuses on successful SSH connections (ACCEPT action), helping security teams understand who is accessing systems remotely, from which source IP addresses, and the frequency of such access. This information is valuable for ensuring compliance with access control policies, identifying potential credential theft, and validating that administrative access follows expected patterns.

**References**:

* [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
* [MITRE ATT&CK: Remote Services](https://attack.mitre.org/techniques/T1021/)
* [MITRE ATT&CK: SSH](https://attack.mitre.org/techniques/T1021/004/)
* [AWS Security Best Practices for SSH](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html)
* [CIS Amazon Web Services Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services/) 