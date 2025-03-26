## Overview

Detect when a VPC network flow established a connection to web services on non-standard ports (excluding common ports 80, 443, 8080, 8443). Web services running on unusual ports may indicate potential security control evasion techniques, command and control channels, or misconfigured services. Monitoring connections to non-standard web ports helps identify adversaries attempting to bypass port-based filtering, maintain persistence through covert channels, or exploit misconfigured services that may have weaker security controls.

**References**:
- [Detecting Suspicious Web Traffic on Non-Standard Ports](https://aws.amazon.com/blogs/security/how-to-use-amazon-guardduty-and-vpc-flow-logs-to-identify-suspicious-traffic/)
- [Protecting Web Applications Against Command and Control Activities](https://aws.amazon.com/blogs/security/how-to-detect-and-automatically-remediate-potentially-malicious-activity-with-aws-lambda-guardduty-security-hub/)
- [Using AWS WAF to Secure Web Applications on Non-Standard Ports](https://aws.amazon.com/blogs/security/how-to-import-your-web-access-control-lists-from-aws-waf-classic-to-new-aws-waf/)
- [Monitoring for Unusual Web Traffic Patterns in AWS](https://aws.amazon.com/blogs/security/how-to-get-started-with-security-monitoring-on-aws/)
- [Implementing Port-Based Security Controls with AWS Network Firewall](https://aws.amazon.com/blogs/networking-and-content-delivery/building-a-service-centric-network-architecture-using-aws-network-firewall/)