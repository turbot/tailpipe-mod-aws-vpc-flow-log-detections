benchmark "protocol_detections" {
  title       = "Protocol Detections"
  description = "This benchmark contains protocol-based security detections when analyzing VPC flow logs."
  type        = "detection"
  children = [
    detection.traffic_with_unusual_protocols
  ]

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    type = "Benchmark"
  })
}

detection "traffic_with_unusual_protocols" {
  title           = "Traffic With Unusual Protocols"
  description     = "Detect unusual protocol usage in VPC Flow Logs to check for potential tunneling, covert channels, or command and control communications."
  documentation   = file("./detections/docs/traffic_with_unusual_protocols.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.traffic_with_unusual_protocols

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    mitre_attack_ids = "TA0011:T1071.001"
  })
}

query "traffic_with_unusual_protocols" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      protocol not in (6, 17, 1) -- Not TCP, UDP, or ICMP
      and action = 'ACCEPT'
    order by
      tp_timestamp desc;
  EOQ
}
