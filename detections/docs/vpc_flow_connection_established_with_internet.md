## Overview

Detect when a VPC network flow established a direct connection to the internet. Direct internet connections may indicate potential data exfiltration channels, command and control activity, or improperly configured security controls that bypass intended network boundaries. Monitoring outbound internet connections helps identify instances that should be operating within private network segments, detect unauthorized data transfers, and validate that network traffic flows through appropriate security inspection points.

**References**:
- [Securing Outbound VPC Traffic with AWS Network Firewall](https://aws.amazon.com/blogs/networking-and-content-delivery/securing-egress-using-aws-network-firewall/)
- [Detecting Data Exfiltration in AWS Environments](https://aws.amazon.com/blogs/security/how-to-help-protect-data-exfiltration-via-aws-managed-services-with-slack-notifications/)
- [Monitoring for Unauthorized Internet Access in AWS](https://aws.amazon.com/blogs/security/how-to-identify-manage-internet-facing-resources-within-your-account/)
- [Implementing Secure Traffic Inspection for Internet Communications](https://aws.amazon.com/blogs/networking-and-content-delivery/centralized-inspection-architecture-with-aws-gateway-load-balancer-and-aws-transit-gateway/)
- [Protecting Against Command and Control Using AWS Network Controls](https://aws.amazon.com/blogs/security/how-to-use-amazon-guardduty-and-amazon-detective-to-identify-and-remediate-cryptocurrency-mining/)