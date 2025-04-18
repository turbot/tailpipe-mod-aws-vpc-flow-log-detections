benchmark "data_transfer_detections" {
  title       = "Data Transfer Detections"
  description = "This benchmark contains data transfer and volume-based security detections when analyzing VPC flow logs."
  type        = "detection"
  children = [
    detection.high_packet_traffic,
    detection.large_data_transfer
  ]

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    type = "Benchmark"
  })
}

detection "large_data_transfer" {
  title           = "Large Data Transfer"
  description     = "Detect large data transfers in VPC Flow Logs to check for potential data exfiltration, unauthorized data transfers, or compromise of cloud resources."
  documentation   = file("./detections/docs/large_data_transfer.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.large_data_transfer

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    mitre_attack_ids = "TA0010:T1048"
  })
}

query "large_data_transfer" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      bytes > 500000000 -- More than 500MB in a single flow
      and action = 'ACCEPT'
    order by
      bytes desc,
      tp_timestamp desc;
  EOQ
}

detection "high_packet_traffic" {
  title           = "High Packet Traffic"
  description     = "Detect high packet volume in VPC Flow Logs to check for potential scanning, denial of service attacks, or other abnormal network behaviors."
  documentation   = file("./detections/docs/high_packet_traffic.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.high_packet_traffic

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    mitre_attack_ids = "TA0040:T1498"
  })
}

query "high_packet_traffic" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      packets > 10000
      and action = 'ACCEPT'
    order by
      packets desc,
      tp_timestamp desc;
  EOQ
}
