## Overview

Detect when a VPC network flow established a connection to high ephemeral ports (49000-65535). While ephemeral ports are commonly used for legitimate return traffic, connections specifically targeting these high ports may indicate potential command and control channels, non-standard services, or data exfiltration attempts. Monitoring connections to unusual high ports helps identify adversaries using non-standard communication methods to maintain persistence or exfiltrate data while attempting to evade detection by security controls.

**References**:
- [Implementing AWS Network Firewall Rules for High Port Protection](https://aws.amazon.com/blogs/networking-and-content-delivery/deployment-models-for-aws-network-firewall-with-vpc-routing-enhancements/)