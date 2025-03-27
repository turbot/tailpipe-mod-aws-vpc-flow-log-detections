## Overview

Detect when a VPC network flow transferred an unusually large amount of data. High-volume data transfers that deviate from normal network traffic patterns could indicate potential data exfiltration attempts, unauthorized data transfers, or compromised cloud resources. Monitoring data transfer volumes helps identify suspicious activities such as lateral movement within your environment, the exploitation of cloud storage resources, or mass data downloads that may suggest credential compromise or insider threats.

**References**:
- [VPC Flow Logs Documentation](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [Monitoring VPC Traffic](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-monitoring.html)
- [AWS Security Best Practices](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [Data Exfiltration Protection](https://aws.amazon.com/blogs/security/how-to-help-protect-data-exfiltration-with-aws-network-firewall/)
- [Analyzing VPC Flow Logs with Amazon Athena](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-athena.html)