## Overview

Detect when a VPC network flow established a connection using unusual protocols (non-TCP, UDP, or ICMP). Unusual protocol usage may indicate potential tunneling techniques, covert communication channels, or command and control traffic attempting to evade security controls. Monitoring for uncommon protocols helps identify adversaries using non-standard communication methods to maintain persistence, exfiltrate data, or control compromised systems while bypassing traditional detection mechanisms focused on common protocols.

**References**:
- [Network Traffic Analysis for Unusual Protocol Activity](https://aws.amazon.com/blogs/security/how-to-use-amazon-guardduty-and-vpc-flow-logs-to-identify-suspicious-traffic/)
- [Detecting Command and Control Using VPC Flow Logs](https://aws.amazon.com/blogs/security/how-to-detect-analyze-and-respond-to-security-threats-using-amazon-guardduty-and-amazon-detective/)
- [Implementing Network Layer Controls Using AWS Network Firewall](https://aws.amazon.com/blogs/networking-and-content-delivery/deployment-models-for-aws-network-firewall/)
- [Protocol-Based Threat Detection in AWS](https://aws.amazon.com/blogs/security/detecting-and-remediating-aws-security-hub-controls-with-aws-config-and-aws-cloudformation/)
- [Monitoring Protocol Behavior with Amazon Detective](https://aws.amazon.com/blogs/security/how-to-investigate-vpc-flow-with-amazon-detective/)