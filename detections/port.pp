benchmark "port_detections" {
  title       = "Port Detections"
  description = "This benchmark contains port-based security detections when analyzing VPC flow logs."
  type        = "detection"
  children = [
    detection.database_traffic,
    detection.rdp_traffic,
    detection.ssh_traffic
  ]

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    type = "Benchmark"
  })
}

detection "ssh_traffic" {
  title           = "SSH Traffic"
  description     = "Detect SSH connections in VPC Flow Logs to check for potential unauthorized access, lateral movement, or command and control activities."
  documentation   = file("./detections/docs/ssh_traffic.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.ssh_traffic

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    mitre_attack_ids = "TA0008:T1021.004"
  })
}

query "ssh_traffic" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      dst_port = 22
    order by
      tp_timestamp desc;
  EOQ
}

detection "rdp_traffic" {
  title           = "RDP Traffic"
  description     = "Detect RDP connections in VPC Flow Logs to check for potential unauthorized access, lateral movement, or command and control activities."
  documentation   = file("./detections/docs/rdp_traffic.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.rdp_traffic

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    mitre_attack_ids = "TA0008:T1021.001"
  })
}

query "rdp_traffic" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      dst_port = 3389
    order by
      tp_timestamp desc;
  EOQ
}

detection "database_traffic" {
  title           = "Database Traffic"
  description     = "Detect database connections in VPC Flow Logs to check for potential unauthorized access, data exfiltration, or lateral movement activities."
  documentation   = file("./detections/docs/database_traffic.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.database_traffic

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    mitre_attack_ids = "TA0008:T1210"
  })
}

query "database_traffic" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_vpc_flow_log
    where
      dst_port in (
        -- AWS Aurora
        1150,
        -- Microsoft SQL Server
        1433,
        1434,
        -- Oracle
        1521,
        1522,
        1526,
        -- MySQL/MariaDB
        3306,
        3307,
        -- PostgreSQL
        5432,
        5433,
        -- CouchDB
        5984,
        -- Redis/ElastiCache
        6379,
        6380,
        6381,
        6382,
        6383,
        -- Cassandra/Keyspaces
        7000,
        7001,
        9042,
        9160,
        -- Caching/Key-Value Stores
        -- ArangoDB
        8529,
        -- Memcached
        11211,
        -- MongoDB/DocumentDB
        27017,
        27018,
        27019,
      )
      and action = 'ACCEPT'
    order by
      tp_timestamp desc;
  EOQ
}

