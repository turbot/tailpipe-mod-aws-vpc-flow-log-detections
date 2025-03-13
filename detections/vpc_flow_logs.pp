benchmark "vpc_flow_log_detections" {
  title       = "VPC Flow Log Detections"
  description = "Detection benchmark containing security alerts derived from analyzing AWS VPC Flow Log data."
  type        = "detection"
  children = [
    detection.vpc_flow_log_connection_rejected,
    detection.vpc_flow_log_log_skipped,
    detection.vpc_flow_log_high_bytes_transfer,
    detection.vpc_flow_log_ssh_access,
    detection.vpc_flow_log_rdp_access,
    detection.vpc_flow_log_database_access,
    detection.vpc_flow_log_unusual_protocol,
    detection.vpc_flow_log_high_packet_count,
    detection.vpc_flow_log_icmp_traffic,
    detection.vpc_flow_log_metadata_service_access,
    detection.vpc_flow_log_ephemeral_port_traffic,
    detection.vpc_flow_log_non_standard_web_ports,
    detection.vpc_flow_log_direct_internet_access
  ]

  tags = local.vpc_flow_log_detections_common_tags
}

/*
 * Detections and queries
 */

detection "vpc_flow_log_connection_rejected" {
  title       = "VPC Flow Log Connection Rejected"
  description = "Detect when a connection is rejected by the VPC Flow Log."
  severity    = "medium"
  query       = query.vpc_flow_log_connection_rejected

  tags = local.vpc_flow_log_detections_common_tags
}

query "vpc_flow_log_connection_rejected" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      action = 'REJECT'
      order by
        tp_timestamp desc;
  EOQ
}

detection "vpc_flow_log_log_skipped" {
  title       = "VPC Flow Log Log Skipped"
  description = "Detect when the VPC Flow Log skipped during the aggregation interval. This indicates an internal AWS capacity constraint or internal error."
  severity    = "medium"
  query       = query.vpc_flow_log_log_skipped

  tags = local.vpc_flow_log_detections_common_tags
}

query "vpc_flow_log_log_skipped" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      log_status = 'SKIPDATA'
      order by
        tp_timestamp desc;
  EOQ
}

detection "vpc_flow_log_high_bytes_transfer" {
  title       = "VPC Flow Log High Bytes Transfer"
  description = "Detect large data transfers that might indicate data exfiltration or unauthorized data movement."
  severity    = "medium"
  query       = query.vpc_flow_log_high_bytes_transfer

  tags = local.vpc_flow_log_detections_common_tags
}

query "vpc_flow_log_high_bytes_transfer" {
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

detection "vpc_flow_log_ssh_access" {
  title       = "VPC Flow Log SSH Access"
  description = "Detect SSH connections to instances, which should be monitored for security purposes."
  severity    = "medium"
  query       = query.vpc_flow_log_ssh_access

  tags = local.vpc_flow_log_detections_common_tags
}

query "vpc_flow_log_ssh_access" {
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

detection "vpc_flow_log_rdp_access" {
  title       = "VPC Flow Log RDP Access"
  description = "Detect RDP connections to instances, which should be monitored for security purposes."
  severity    = "medium"
  query       = query.vpc_flow_log_rdp_access

  tags = local.vpc_flow_log_detections_common_tags
}

query "vpc_flow_log_rdp_access" {
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

detection "vpc_flow_log_database_access" {
  title       = "VPC Flow Log Database Access"
  description = "Detect connections to common database ports, which should be monitored for security purposes."
  severity    = "medium"
  query       = query.vpc_flow_log_database_access

  tags = local.vpc_flow_log_detections_common_tags
}

query "vpc_flow_log_database_access" {
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

detection "vpc_flow_log_unusual_protocol" {
  title       = "VPC Flow Log Unusual Protocol"
  description = "Detect traffic using unusual protocols that might indicate tunneling or covert channels."
  severity    = "medium"
  query       = query.vpc_flow_log_unusual_protocol

  tags = local.vpc_flow_log_detections_common_tags
}

query "vpc_flow_log_unusual_protocol" {
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

detection "vpc_flow_log_high_packet_count" {
  title       = "VPC Flow Log High Packet Count"
  description = "Detect flows with an unusually high packet count which might indicate scanning, DDoS, or other unusual activity."
  severity    = "medium"
  query       = query.vpc_flow_log_high_packet_count

  tags = local.vpc_flow_log_detections_common_tags
}

query "vpc_flow_log_high_packet_count" {
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

detection "vpc_flow_log_icmp_traffic" {
  title       = "VPC Flow Log ICMP Traffic"
  description = "Detect ICMP traffic which might indicate ping sweeps, network diagnostics, or reconnaissance."
  severity    = "low"
  query       = query.vpc_flow_log_icmp_traffic

  tags = local.vpc_flow_log_detections_common_tags
}

query "vpc_flow_log_icmp_traffic" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      protocol = 1 -- ICMP
    order by
      tp_timestamp desc;
  EOQ
}

detection "vpc_flow_log_metadata_service_access" {
  title       = "VPC Flow Log EC2 Metadata Service Access"
  description = "Detect traffic to the EC2 metadata service IP address, which could indicate attempts to gather instance information."
  severity    = "medium"
  query       = query.vpc_flow_log_metadata_service_access

  tags = local.vpc_flow_log_detections_common_tags
}

query "vpc_flow_log_metadata_service_access" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      dst_addr = '169.254.169.254'
    order by
      tp_timestamp desc;
  EOQ
}

detection "vpc_flow_log_ephemeral_port_traffic" {
  title       = "VPC Flow Log Ephemeral Port Traffic"
  description = "Detect traffic on high ephemeral ports, which might indicate dynamic services or command and control traffic."
  severity    = "low"
  query       = query.vpc_flow_log_ephemeral_port_traffic

  tags = local.vpc_flow_log_detections_common_tags
}

query "vpc_flow_log_ephemeral_port_traffic" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      dst_port > 49000
      and dst_port < 65535
      and action = 'ACCEPT'
    order by
      tp_timestamp desc;
  EOQ
}

detection "vpc_flow_log_non_standard_web_ports" {
  title       = "VPC Flow Log Non-Standard Web Ports"
  description = "Detect web traffic on non-standard ports, which might indicate web services running on unusual ports or attempts to evade security controls."
  severity    = "low"
  query       = query.vpc_flow_log_non_standard_web_ports

  tags = local.vpc_flow_log_detections_common_tags
}

query "vpc_flow_log_non_standard_web_ports" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      dst_port not in (80, 443, 8080, 8443)
      and action = 'ACCEPT'
      and (
        dst_port between 7000 and 9000
        or dst_port between 3000 and 5000
        or dst_port in (81, 591, 2080, 2443, 4343, 7070, 7080, 7443, 7900, 8008, 8081, 8181, 8444, 9080, 9443)
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "vpc_flow_log_direct_internet_access" {
  title       = "VPC Flow Log Direct Internet Access"
  description = "Detect traffic directly to the internet (not through NAT Gateway or other AWS service), which might indicate improperly configured security."
  severity    = "medium"
  query       = query.vpc_flow_log_direct_internet_access

  tags = local.vpc_flow_log_detections_common_tags
}

query "vpc_flow_log_direct_internet_access" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      flow_direction = 'egress'
      and (dst_addr not like '10.%' and dst_addr not like '172.1_.%' and dst_addr not like '172.2_.%' and dst_addr not like '172.3_.%' and dst_addr not like '192.168.%')
      and dst_addr not like '169.254.%'
      and action = 'ACCEPT'
    order by
      tp_timestamp desc;
  EOQ
}
