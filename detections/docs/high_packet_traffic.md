## Overview

Detect high packet volume in VPC Flow Logs. High-volume data transfers that deviate from normal network traffic patterns could indicate potential data exfiltration attempts, unauthorized data transfers, or compromised cloud resources. Monitoring data transfer volumes helps identify suspicious activities such as lateral movement within your environment, the exploitation of cloud storage resources, or mass data downloads that may suggest credential compromise or insider threats.

This detection monitors only accepted traffic and alerts on flows with more than 10,000 packets.

**References**:
- [VPC Security Best Practices](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html#security-groups)
