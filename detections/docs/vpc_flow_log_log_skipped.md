# Overview

This detection identifies instances where VPC Flow Log records are skipped during the aggregation interval, indicating potential internal AWS capacity constraints or errors. When the AWS Flow Logs service encounters limitations in processing capacity, it may skip logging some network flows, resulting in gaps in your security monitoring data.

Monitoring for skipped logs helps ensure the completeness and integrity of your network traffic logs, which are critical for security analysis, incident response, and compliance purposes. Persistent or increasing patterns of skipped logs should be investigated, as they could indicate issues with the Flow Logs configuration, service limitations, or high traffic volumes that exceed service thresholds.

**References**:

* [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
* [VPC Flow Logs Record Format](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-syntax.html)
* [Flow Logs Limitations](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-limitations.html)
* [AWS Monitoring and Observability Best Practices](https://docs.aws.amazon.com/wellarchitected/latest/management-and-governance-lens/observability.html) 