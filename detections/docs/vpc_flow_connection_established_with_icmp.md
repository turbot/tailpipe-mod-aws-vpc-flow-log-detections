## Overview

Detect when a VPC network flow used ICMP protocol. While ICMP serves legitimate network diagnostic purposes, it's also commonly used for reconnaissance activities such as ping sweeps, network mapping, and host discovery. Monitoring ICMP traffic helps identify potential adversary reconnaissance that precedes targeted attacks, allowing for early detection of network discovery attempts and other suspicious activities directed at your AWS infrastructure.

**References**:
- [Protecting Against ICMP-Based Attacks in AWS](https://aws.amazon.com/blogs/networking-and-content-delivery/scaling-network-traffic-inspection-using-aws-gateway-load-balancer/)