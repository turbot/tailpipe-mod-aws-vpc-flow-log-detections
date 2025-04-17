benchmark "vpc_flow_log_detections" {
  title       = "VPC Flow Log Detections"
  description = "Detection benchmark containing security alerts derived from analyzing AWS VPC Flow Log data."
  type        = "detection"
  children = [
    detection.vpc_flow_connection_rejected,
    detection.vpc_flow_connection_skipped,
    detection.vpc_flow_connection_transferred_with_high_volume,
    detection.vpc_flow_connection_established_with_ssh,
    detection.vpc_flow_connection_established_with_rdp,
    detection.vpc_flow_connection_established_with_database,
    detection.vpc_flow_connection_established_with_unusual_protocol,
    detection.vpc_flow_connection_transferred_with_high_packet_count,
  ]

  tags = local.vpc_flow_log_detections_common_tags
}

/*
 * Detections and queries
 */

detection "vpc_flow_connection_rejected" {
  title           = "VPC Flow Connection Rejected"
  description     = "Detect when a connection was rejected in VPC Flow Logs to check for potential security group issues, network misconfigurations, or failed intrusion attempts."
  documentation   = file("./detections/docs/vpc_flow_connection_rejected.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.vpc_flow_connection_rejected

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    mitre_attack_ids = "TA0011:T1046"
  })
}

query "vpc_flow_connection_rejected" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      action = 'REJECT'
      -- Additional filtering to reduce noise, for example:
      and bytes > 0
    order by
      tp_timestamp desc;
  EOQ
}

detection "vpc_flow_connection_skipped" {
  title           = "VPC Flow Logs Skipped"
  description     = "Detect when VPC Flow Logs were skipped during the aggregation interval to check for potential gaps in network visibility that could mask malicious activity or compliance violations."
  documentation   = file("./detections/docs/vpc_flow_connection_skipped.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.vpc_flow_connection_skipped

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "vpc_flow_connection_skipped" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      log_status in ('NODATA', 'SKIPDATA')
    order by
      tp_timestamp desc;
  EOQ
}

detection "vpc_flow_connection_transferred_with_high_volume" {
  title           = "VPC Flow Connection Transferred With High Volume"
  description     = "Detect when a VPC network flow transferred an unusually large amount of data to check for potential data exfiltration, unauthorized data transfers, or compromise of cloud resources."
  documentation   = file("./detections/docs/vpc_flow_connection_transferred_with_high_volume.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.vpc_flow_connection_transferred_with_high_volume

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    mitre_attack_ids = "TA0010:T1048"
  })
}

query "vpc_flow_connection_transferred_with_high_volume" {
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

detection "vpc_flow_connection_established_with_ssh" {
  title           = "VPC Flow Connection Established With SSH"
  description     = "Detect when a VPC network flow established an SSH connection to check for potential unauthorized access, lateral movement, or command and control activities."
  documentation   = file("./detections/docs/vpc_flow_connection_established_with_ssh.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.vpc_flow_connection_established_with_ssh

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    mitre_attack_ids = "TA0008:T1021.004"
  })
}

query "vpc_flow_connection_established_with_ssh" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      dst_port = 22
      and action = 'ACCEPT'
    order by
      tp_timestamp desc;
  EOQ
}

detection "vpc_flow_connection_established_with_rdp" {
  title           = "VPC Flow Connection Established With RDP"
  description     = "Detect when a VPC network flow established an RDP connection to check for potential unauthorized access, lateral movement, or command and control activities."
  documentation   = file("./detections/docs/vpc_flow_connection_established_with_rdp.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.vpc_flow_connection_established_with_rdp

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    mitre_attack_ids = "TA0008:T1021.001"
  })
}

query "vpc_flow_connection_established_with_rdp" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      dst_port = 3389
      and action = 'ACCEPT'
    order by
      tp_timestamp desc;
  EOQ
}

detection "vpc_flow_connection_established_with_database" {
  title           = "VPC Flow Connection Established With Database"
  description     = "Detect when a VPC network flow established a connection to database ports to check for potential unauthorized access, data exfiltration, or lateral movement activities."
  documentation   = file("./detections/docs/vpc_flow_connection_established_with_database.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.vpc_flow_connection_established_with_database

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    mitre_attack_ids = "TA0008:T1210"
  })
}

query "vpc_flow_connection_established_with_database" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      dst_port in (3306, 5432, 1433, 1521, 27017, 6379, 9042)
      and action = 'ACCEPT'
    order by
      tp_timestamp desc;
  EOQ
}

detection "vpc_flow_connection_established_with_unusual_protocol" {
  title           = "VPC Flow Connection Established With Unusual Protocol"
  description     = "Detect when a VPC network flow established a connection using unusual protocols to check for potential tunneling, covert channels, or command and control communications."
  documentation   = file("./detections/docs/vpc_flow_connection_established_with_unusual_protocol.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.vpc_flow_connection_established_with_unusual_protocol

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    mitre_attack_ids = "TA0011:T1071.001"
  })
}

query "vpc_flow_connection_established_with_unusual_protocol" {
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

detection "vpc_flow_connection_transferred_with_high_packet_count" {
  title           = "VPC Flow Connection Transferred With High Packet Count"
  description     = "Detect when a VPC network flow transferred an unusually high number of packets to check for potential scanning, denial of service attacks, or other abnormal network behaviors."
  documentation   = file("./detections/docs/vpc_flow_connection_transferred_with_high_packet_count.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.vpc_flow_connection_transferred_with_high_packet_count

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    mitre_attack_ids = "TA0040:T1498"
  })
}

query "vpc_flow_connection_transferred_with_high_packet_count" {
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

