# Overview

This detection monitors for large data transfers that may indicate data exfiltration or unauthorized data movement. Unusually large volumes of data being transferred, especially to external destinations, could represent attempts to extract sensitive information from your environment. 

The detection identifies network flows with unusually large data volumes (over 500MB in a single flow) and highlights them for investigation. While legitimate applications may transfer large amounts of data, unexpected or unusual large transfers should be reviewed, particularly when they involve sensitive systems or external destinations. This detection serves as an important control for identifying potential data exfiltration attempts, misconfigurations, or unauthorized data access.

**References**:

* [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
* [MITRE ATT&CK: Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
* [MITRE ATT&CK: Data Exfiltration](https://attack.mitre.org/tactics/TA0010/)
* [AWS Security Best Practices](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
* [AWS CloudWatch Metrics for VPC](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-cloudwatch.html) 