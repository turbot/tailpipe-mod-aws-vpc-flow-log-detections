## Overview

Detect when a VPC network flow established a direct connection to the internet. Direct internet connections may indicate potential data exfiltration channels, command and control activity, or improperly configured security controls that bypass intended network boundaries. Monitoring outbound internet connections helps identify instances that should be operating within private network segments, detect unauthorized data transfers, and validate that network traffic flows through appropriate security inspection points.

**References**:
- [Implementing Secure Traffic Inspection for Internet Communications](https://aws.amazon.com/blogs/networking-and-content-delivery/centralized-inspection-architecture-with-aws-gateway-load-balancer-and-aws-transit-gateway/)