# Overview

This detection identifies instances where a single source IP address generates an unusually high volume of connections to your AWS environment, which could indicate scanning, brute force attempts, or denial of service activities. While normal traffic patterns typically involve a moderate number of connections from legitimate sources, attack traffic often involves hundreds or thousands of connection attempts in a short period.

The detection analyzes VPC Flow Logs to identify source IP addresses that initiate an abnormally high number of connections to your resources within a defined time window. By establishing baselines for normal connection volumes and alerting on significant deviations, this detection helps identify potential reconnaissance or exploitation attempts before they succeed, as well as potential denial of service attacks targeting your infrastructure.

**References**:

* [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
* [MITRE ATT&CK: Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
* [MITRE ATT&CK: Brute Force](https://attack.mitre.org/techniques/T1110/)
* [AWS DDoS Resilience](https://docs.aws.amazon.com/whitepapers/latest/aws-best-practices-ddos-resiliency/welcome.html)
* [AWS Shield](https://aws.amazon.com/shield/) 