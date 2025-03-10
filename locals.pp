locals {
  vpc_flow_log_detections_common_tags = {
    service       = "aws_vpc_flow_logs",
    plugin        = "aws",
    category      = "security",
    documentation = "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"
  }

  // Common display columns for detections
  flow_log_detection_display_columns = [
    "time",
    "severity",
    "source_ip",
    "destination_ip",
    "destination_port",
    "protocol",
    "bytes",
    "region",
    "account_id"
  ]

  // MITRE ATT&CK mapping
  mitre_attack_mappings = {
    reconnaissance = "TA0043",
    resource_development = "TA0042",
    initial_access = "TA0001",
    execution = "TA0002",
    persistence = "TA0003",
    privilege_escalation = "TA0004",
    defense_evasion = "TA0005",
    credential_access = "TA0006",
    discovery = "TA0007",
    lateral_movement = "TA0008",
    collection = "TA0009",
    exfiltration = "TA0010",
    command_and_control = "TA0011",
    impact = "TA0040"
  }

  // Common SQL resource columns for reporting
  detection_sql_resource_column_flow_log = <<-EOQ
    tp_id as id,
    tp_timestamp as time,
    src_addr as source_ip,
    dst_addr as destination_ip, 
    dst_port as destination_port,
    protocol,
    bytes,
    region,
    account_id,
    vpc_id,
    interface_id,
    instance_id
  EOQ
} 