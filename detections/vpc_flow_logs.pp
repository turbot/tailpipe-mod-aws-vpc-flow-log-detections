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
    detection.vpc_flow_connection_established_with_icmp,
    detection.vpc_flow_connection_established_with_ephemeral_ports,
    detection.vpc_flow_connection_established_with_non_standard_web_ports,
    detection.vpc_flow_connection_established_with_internet
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
  display_columns = local.vpc_flow_log_display_columns
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
  severity        = "medium"
  display_columns = local.vpc_flow_log_display_columns
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
      log_status = 'SKIPDATA'
    order by
      tp_timestamp desc;
  EOQ
}

detection "vpc_flow_connection_transferred_with_high_volume" {
  title           = "VPC Flow Connection Transferred With High Volume"
  description     = "Detect when a VPC network flow transferred an unusually large amount of data to check for potential data exfiltration, unauthorized data transfers, or compromise of cloud resources."
  documentation   = file("./detections/docs/vpc_flow_connection_transferred_with_high_volume.md")
  severity        = "medium"
  display_columns = local.vpc_flow_log_display_columns
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
  display_columns = local.vpc_flow_log_display_columns
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
  display_columns = local.vpc_flow_log_display_columns
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
  display_columns = local.vpc_flow_log_display_columns
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
  display_columns = local.vpc_flow_log_display_columns
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
  display_columns = local.vpc_flow_log_display_columns
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

detection "vpc_flow_connection_established_with_icmp" {
  title           = "VPC Flow Connection Established With ICMP"
  description     = "Detect when a VPC network flow used ICMP protocol to check for potential reconnaissance activities, ping sweeps, or network mapping attempts."
  documentation   = file("./detections/docs/vpc_flow_connection_established_with_icmp.md")
  severity        = "low"
  display_columns = local.vpc_flow_log_display_columns
  query           = query.vpc_flow_connection_established_with_icmp

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    mitre_attack_ids = "TA0043:T1595.001"
  })
}

query "vpc_flow_connection_established_with_icmp" {
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

detection "vpc_flow_connection_established_with_ephemeral_ports" {
  title           = "VPC Flow Connection Established With Ephemeral Ports"
  description     = "Detect when a VPC network flow established a connection to high ephemeral ports to check for potential command and control channels, non-standard services, or data exfiltration attempts."
  documentation   = file("./detections/docs/vpc_flow_connection_established_with_ephemeral_ports.md")
  severity        = "low"
  display_columns = local.vpc_flow_log_display_columns
  query           = query.vpc_flow_connection_established_with_ephemeral_ports

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    mitre_attack_ids = "TA0011:T1571"
  })
}

query "vpc_flow_connection_established_with_ephemeral_ports" {
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

detection "vpc_flow_connection_established_with_non_standard_web_ports" {
  title           = "VPC Flow Connection Established With Non-Standard Web Ports"
  description     = "Detect when a VPC network flow established a connection to web services on non-standard ports to check for potential security control evasion, command and control channels, or misconfigured services."
  documentation   = file("./detections/docs/vpc_flow_connection_established_with_non_standard_web_ports.md")
  severity        = "low"
  display_columns = local.vpc_flow_log_display_columns
  query           = query.vpc_flow_connection_established_with_non_standard_web_ports

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    mitre_attack_ids = "TA0011:T1571"
  })
}

query "vpc_flow_connection_established_with_non_standard_web_ports" {
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

detection "vpc_flow_connection_established_with_internet" {
  title           = "VPC Flow Connection Established With Internet"
  description     = "Detect when a VPC network flow established a direct connection to the internet to check for potential data exfiltration, command and control activity, or improperly configured security controls."
  documentation   = file("./detections/docs/vpc_flow_connection_established_with_internet.md")
  severity        = "medium"
  display_columns = local.vpc_flow_log_display_columns
  query           = query.vpc_flow_connection_established_with_internet

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    mitre_attack_ids = "TA0011:T1133"
  })
}

query "vpc_flow_connection_established_with_internet" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      flow_direction = 'egress'
      and action = 'ACCEPT'
      -- Exclude RFC1918 private IP ranges (IPv4)
      and (
        dst_addr not like '10.%' 
        and (dst_addr not between '172.16.0.0' and '172.31.255.255')
        and dst_addr not like '192.168.%'
      )
      -- Exclude link-local addresses
      and dst_addr not like '169.254.%'
      -- Exclude RFC4193 private IP ranges (IPv6)
      and dst_addr not like 'fc00:%'
      and dst_addr not like 'fd00:%'
    order by
      tp_timestamp desc;
  EOQ
}
