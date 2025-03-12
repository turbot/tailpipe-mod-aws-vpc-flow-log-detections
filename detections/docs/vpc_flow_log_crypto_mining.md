# Overview

This detection identifies network connections to known cryptocurrency mining pools, which could indicate unauthorized cryptocurrency mining activity on your AWS infrastructure. Crypto mining on company resources without authorization (cryptojacking) is a common form of resource theft that consumes CPU cycles, increases electricity costs, and may indicate a security compromise.

The detection analyzes VPC Flow Logs to identify connections to IP addresses and ports associated with popular mining pools and protocols. Unauthorized crypto mining activity not only impacts performance and costs but also may indicate other security issues, as cryptojacking is often deployed alongside other malware or following a successful compromise. Early detection of mining activity can help identify compromised instances and prevent significant resource consumption and associated costs.

**References**:

* [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
* [MITRE ATT&CK: Resource Hijacking](https://attack.mitre.org/techniques/T1496/)
* [AWS Compromised EC2 Instance Response](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/compromised-ec2-instance.html)
* [AWS Shield Protections](https://docs.aws.amazon.com/waf/latest/developerguide/shield-chapter.html)
* [Cloud Security Alliance: Top Threats to Cloud Computing](https://cloudsecurityalliance.org/research/topics/top-threats/) 