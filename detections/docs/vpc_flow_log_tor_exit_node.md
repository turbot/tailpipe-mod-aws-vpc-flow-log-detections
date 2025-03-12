# Overview

This detection identifies network connections involving known Tor exit nodes, which may indicate attempts to maintain anonymity while accessing your AWS resources. Tor is an anonymity network that routes traffic through multiple relays, with exit nodes being the final relay where traffic exits the Tor network. While Tor has legitimate uses for privacy, connections from Tor exit nodes to corporate infrastructure often indicate attempts to hide identity for malicious purposes.

The detection compares source IP addresses in VPC Flow Logs against known Tor exit node lists to identify potential anonymous access to your resources. This helps security teams detect possible malicious actors using Tor to obscure their identity while conducting unauthorized activities, such as reconnaissance, exploitation attempts, or accessing compromised systems.

**References**:

* [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
* [MITRE ATT&CK: Proxy](https://attack.mitre.org/techniques/T1090/)
* [MITRE ATT&CK: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003/)
* [Tor Project](https://www.torproject.org/)
* [AWS Network Security Best Practices](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/network-monitoring.html) 