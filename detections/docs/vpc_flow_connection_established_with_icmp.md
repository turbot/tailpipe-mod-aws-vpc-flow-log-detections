## Overview

Detect when a VPC network flow used ICMP protocol. While ICMP serves legitimate network diagnostic purposes, it's also commonly used for reconnaissance activities such as ping sweeps, network mapping, and host discovery. Monitoring ICMP traffic helps identify potential adversary reconnaissance that precedes targeted attacks, allowing for early detection of network discovery attempts and other suspicious activities directed at your AWS infrastructure.

**References**:
- [Detecting Network Reconnaissance with VPC Flow Logs](https://aws.amazon.com/blogs/security/how-to-use-amazon-guardduty-and-vpc-flow-logs-to-identify-suspicious-traffic/)
- [Protecting Against ICMP-Based Attacks in AWS](https://aws.amazon.com/blogs/networking-and-content-delivery/scaling-network-traffic-inspection-using-aws-gateway-load-balancer/)
- [Configuring Security Groups to Block ICMP Traffic](https://aws.amazon.com/blogs/security/how-to-help-prepare-for-ddos-attacks-by-using-aws-waf-and-shield/)
- [Identifying Host Discovery Attempts with Amazon GuardDuty](https://aws.amazon.com/blogs/security/visualize-amazon-guardduty-investigations-with-amazon-athena-and-amazon-quicksight/)
- [Network Access Analyzer for Detecting Unrestricted ICMP Access](https://aws.amazon.com/blogs/aws/launch-announcing-general-availability-of-vpc-network-access-analyzer/)