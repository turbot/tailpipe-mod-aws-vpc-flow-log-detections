benchmark "vpc_flow_log_detections" {
  title       = "AWS VPC Flow Log Detections"
  description = "Detection benchmark containing security alerts derived from analyzing AWS VPC Flow Log data."
  type        = "detection"
  children = [
    detection.vpc_flow_log_excessive_rejected_connections,
    detection.vpc_flow_log_unusual_port_activity,
    detection.vpc_flow_log_large_data_transfer,
    detection.vpc_flow_log_service_scanning_activity,
    detection.vpc_flow_log_public_service_access,
    detection.vpc_flow_log_suspicious_outbound_traffic,
    detection.vpc_flow_log_internal_port_scanning,
    detection.vpc_flow_log_communication_to_known_bad_ip,
    detection.vpc_flow_log_unusual_protocol_usage,
    detection.vpc_flow_log_unidirectional_traffic_flow
  ]

  tags = {
    service = "aws_vpc_flow_logs",
    plugin  = "aws",
    type    = "Benchmark"
  }
}

/*
 * Detections and queries
 */

detection "vpc_flow_log_excessive_rejected_connections" {
  title       = "Excessive Rejected Connections"
  description = "Identifies instances where a high number of connection attempts are being rejected from a single source to a destination."
  severity    = "medium"
  query       = query.vpc_flow_log_excessive_rejected_connections

  tags = {
    service = "aws_vpc_flow_logs",
    plugin  = "aws"
  }
}

query "vpc_flow_log_excessive_rejected_connections" {
  sql = <<-EOQ
    with rejected_connections as (
      select
        src_addr,
        dst_addr,
        count(*) as reject_count
      from
        aws_vpc_flow_log
      where
        action = 'REJECT'
        and tp_timestamp >= dateadd(hour, -1, current_timestamp)
      group by
        src_addr,
        dst_addr
      having
        count(*) > 50
    )
    
    select
      tp_id as id,
      tp_timestamp as time,
      'Excessive Rejected Connections' as title,
      case
        when reject_count > 200 then 'high'
        when reject_count > 100 then 'medium'
        else 'low'
      end as severity,
      src_addr as source_ip,
      dst_addr as destination_ip,
      reject_count,
      region,
      account_id
    from
      rejected_connections r
      join aws_vpc_flow_log f on r.src_addr = f.src_addr and r.dst_addr = f.dst_addr
    where
      f.action = 'REJECT'
    order by
      reject_count desc,
      tp_timestamp desc
    limit 100
  EOQ
}

detection "vpc_flow_log_unusual_port_activity" {
  title       = "Unusual Port Activity"
  description = "Identifies traffic on uncommon or suspicious ports which might indicate command and control channels or unauthorized services."
  severity    = "medium"
  query       = query.vpc_flow_log_unusual_port_activity

  tags = {
    service = "aws_vpc_flow_logs",
    plugin  = "aws"
  }
}

query "vpc_flow_log_unusual_port_activity" {
  sql = <<-EOQ
    with common_ports as (
      select unnest(array[20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]) as port
    ),
    
    port_activity as (
      select
        dst_port,
        count(*) as connection_count
      from
        aws_vpc_flow_log
      where
        action = 'ACCEPT'
        and tp_timestamp >= dateadd(day, -1, current_timestamp)
        and dst_port is not null
        and dst_port not in (select port from common_ports)
        and dst_port > 1024
      group by
        dst_port
      having
        count(*) > 20
    )
    
    select
      f.tp_id as id,
      f.tp_timestamp as time,
      'Unusual Port Activity: ' || f.dst_port as title,
      case
        when f.dst_port between 6666 and 6669 or f.dst_port = 4444 then 'high'
        when f.dst_port > 50000 then 'medium'
        else 'low'
      end as severity,
      f.src_addr as source_ip,
      f.dst_addr as destination_ip,
      f.dst_port as destination_port,
      p.connection_count,
      f.protocol,
      f.region
    from
      port_activity p
      join aws_vpc_flow_log f on p.dst_port = f.dst_port
    where
      f.action = 'ACCEPT'
    order by
      p.connection_count desc
    limit 100
  EOQ
}

detection "vpc_flow_log_large_data_transfer" {
  title       = "Large Data Transfer"
  description = "Identifies unusually large data transfers which may indicate data exfiltration or unauthorized bulk data movement."
  severity    = "medium"
  query       = query.vpc_flow_log_large_data_transfer

  tags = {
    service = "aws_vpc_flow_logs",
    plugin  = "aws"
  }
}

query "vpc_flow_log_large_data_transfer" {
  sql = <<-EOQ
    with data_transfers as (
      select
        src_addr,
        dst_addr,
        sum(bytes) as total_bytes,
        sum(bytes) / (1024 * 1024) as total_mb
      from
        aws_vpc_flow_log
      where
        tp_timestamp >= dateadd(hour, -6, current_timestamp)
        and action = 'ACCEPT'
      group by
        src_addr,
        dst_addr
      having
        sum(bytes) > (100 * 1024 * 1024) -- More than 100 MB transferred
    )
    
    select
      f.tp_id as id,
      f.tp_timestamp as time,
      'Large Data Transfer: ' || round(dt.total_mb, 2) || ' MB' as title,
      case
        when dt.total_mb > 500 then 'high'
        when dt.total_mb > 200 then 'medium'
        else 'low'
      end as severity,
      dt.src_addr as source_ip,
      dt.dst_addr as destination_ip,
      dt.total_bytes as bytes,
      round(dt.total_mb, 2) as total_mb,
      f.region,
      f.account_id
    from
      data_transfers dt
      join aws_vpc_flow_log f on dt.src_addr = f.src_addr and dt.dst_addr = f.dst_addr
    where
      f.action = 'ACCEPT'
    order by
      dt.total_bytes desc
    limit 100
  EOQ
}

detection "vpc_flow_log_service_scanning_activity" {
  title       = "Service Scanning Activity"
  description = "Detects network scanning patterns where a single source IP attempts to connect to multiple destinations on the same port."
  severity    = "high"
  query       = query.vpc_flow_log_service_scanning_activity

  tags = {
    service = "aws_vpc_flow_logs",
    plugin  = "aws"
  }
}

query "vpc_flow_log_service_scanning_activity" {
  sql = <<-EOQ
    with scanning as (
      select
        src_addr,
        dst_port,
        count(distinct dst_addr) as unique_destinations
      from
        aws_vpc_flow_log
      where
        tp_timestamp >= dateadd(hour, -1, current_timestamp)
        and dst_port is not null
      group by
        src_addr,
        dst_port
      having
        count(distinct dst_addr) > 10 -- Source attempting to connect to at least 10 unique destinations on same port
    )
    
    select
      f.tp_id as id,
      f.tp_timestamp as time,
      'Service Scanning: Port ' || s.dst_port || ' (' || s.unique_destinations || ' targets)' as title,
      case
        when s.unique_destinations > 50 then 'critical'
        when s.unique_destinations > 25 then 'high'
        else 'medium'
      end as severity,
      s.src_addr as source_ip,
      f.dst_addr as destination_ip,
      s.dst_port as destination_port,
      s.unique_destinations,
      f.protocol,
      f.region,
      f.account_id
    from
      scanning s
      join aws_vpc_flow_log f on s.src_addr = f.src_addr and s.dst_port = f.dst_port
    order by
      s.unique_destinations desc
    limit 100
  EOQ
}

detection "vpc_flow_log_public_service_access" {
  title       = "Public Service Access"
  description = "Identifies traffic from public internet IPs to sensitive internal services that should not be publicly accessible."
  severity    = "high"
  query       = query.vpc_flow_log_public_service_access

  tags = {
    service = "aws_vpc_flow_logs",
    plugin  = "aws"
  }
}

query "vpc_flow_log_public_service_access" {
  sql = <<-EOQ
    with sensitive_services as (
      select 
        port,
        service_name
      from (
        values
          (22, 'SSH'),
          (3389, 'RDP'),
          (1433, 'MSSQL'),
          (3306, 'MySQL'),
          (5432, 'PostgreSQL'),
          (6379, 'Redis'),
          (9200, 'Elasticsearch'),
          (27017, 'MongoDB')
      ) as sensitive_ports(port, service_name)
    ),
    
    private_ip_ranges as (
      select cidr from (
        values
          ('10.0.0.0/8'),
          ('172.16.0.0/12'),
          ('192.168.0.0/16')
      ) as private_ranges(cidr)
    )
    
    select
      f.tp_id as id,
      f.tp_timestamp as time,
      'Public Access to ' || s.service_name || ' Service' as title,
      case
        when s.service_name in ('SSH', 'RDP', 'Redis', 'Elasticsearch', 'MongoDB') then 'critical'
        else 'high'
      end as severity,
      f.src_addr as source_ip,
      f.dst_addr as destination_ip,
      f.dst_port as destination_port,
      s.service_name as service,
      f.protocol,
      f.region,
      f.account_id
    from
      aws_vpc_flow_log f
      join sensitive_services s on f.dst_port = s.port
    where
      f.action = 'ACCEPT'
      and f.tp_timestamp >= dateadd(hour, -24, current_timestamp)
      and not exists (
        select 1 from private_ip_ranges p
        where netmask(f.src_addr, p.cidr)
      )
    order by
      f.tp_timestamp desc
    limit 100
  EOQ
}

detection "vpc_flow_log_suspicious_outbound_traffic" {
  title       = "Suspicious Outbound Traffic"
  description = "Identifies unusual outbound traffic to suspicious destinations or known malicious IP addresses."
  severity    = "high"
  query       = query.vpc_flow_log_suspicious_outbound_traffic

  tags = {
    service = "aws_vpc_flow_logs",
    plugin  = "aws"
  }
}

query "vpc_flow_log_suspicious_outbound_traffic" {
  sql = <<-EOQ
    with known_bad_ips as (
      select cidr from (
        values
          ('185.159.151.0/24'),
          ('91.132.255.0/24'),
          ('151.11.107.0/24')
      ) as bad_ranges(cidr)
    ),
    
    suspicious_ports as (
      select port from (
        values
          (6667), -- IRC
          (6697), -- IRC SSL
          (4444), -- Common backdoor port
          (1080), -- SOCKS proxy
          (9001)  -- Tor
      ) as susp_ports(port)
    )
    
    select
      f.tp_id as id,
      f.tp_timestamp as time,
      'Suspicious Outbound Traffic' as title,
      'high' as severity,
      f.src_addr as source_ip,
      f.dst_addr as destination_ip,
      f.dst_port as destination_port,
      case
        when exists (
          select 1 from known_bad_ips b
          where netmask(f.dst_addr, b.cidr)
        ) then 'Known Bad IP Range'
        when exists (
          select 1 from suspicious_ports p
          where f.dst_port = p.port
        ) then 'Suspicious Port'
        else 'Unusual Traffic Pattern'
      end as detection_reason,
      f.protocol,
      f.bytes,
      f.region,
      f.account_id
    from
      aws_vpc_flow_log f
    where
      f.tp_timestamp >= dateadd(day, -1, current_timestamp)
      and f.action = 'ACCEPT'
      and (
        exists (
          select 1 from known_bad_ips b
          where netmask(f.dst_addr, b.cidr)
        )
        or exists (
          select 1 from suspicious_ports p
          where f.dst_port = p.port
        )
      )
    order by
      f.tp_timestamp desc
    limit 100
  EOQ
}

detection "vpc_flow_log_internal_port_scanning" {
  title       = "Internal Port Scanning"
  description = "Detects internal port scanning patterns where a single source IP is attempting to connect to multiple ports on the same destination."
  severity    = "high"
  query       = query.vpc_flow_log_internal_port_scanning

  tags = {
    service = "aws_vpc_flow_logs",
    plugin  = "aws"
  }
}

query "vpc_flow_log_internal_port_scanning" {
  sql = <<-EOQ
    with port_scanning as (
      select
        src_addr,
        dst_addr,
        count(distinct dst_port) as unique_ports_scanned
      from
        aws_vpc_flow_log
      where
        tp_timestamp >= dateadd(hour, -1, current_timestamp)
        -- Only consider internal traffic (private IP ranges)
        and (
          (src_addr like '10.%' or src_addr like '172.1_._._' or src_addr like '192.168.%') 
          and 
          (dst_addr like '10.%' or dst_addr like '172.1_._._' or dst_addr like '192.168.%')
        )
      group by
        src_addr,
        dst_addr
      having
        count(distinct dst_port) > 15
    )
    
    select
      f.tp_id as id,
      f.tp_timestamp as time,
      'Internal Port Scanning: ' || ps.unique_ports_scanned || ' ports on ' || ps.dst_addr as title,
      case
        when ps.unique_ports_scanned > 100 then 'critical'
        when ps.unique_ports_scanned > 50 then 'high'
        else 'medium'
      end as severity,
      ps.src_addr as source_ip,
      ps.dst_addr as destination_ip,
      ps.unique_ports_scanned,
      f.protocol,
      f.region,
      f.account_id
    from
      port_scanning ps
      join aws_vpc_flow_log f on ps.src_addr = f.src_addr and ps.dst_addr = f.dst_addr
    order by
      ps.unique_ports_scanned desc
    limit 100
  EOQ
}

detection "vpc_flow_log_communication_to_known_bad_ip" {
  title       = "Communication to Known Bad IP"
  description = "Detects communication to known malicious IP addresses or threat indicators."
  severity    = "critical"
  query       = query.vpc_flow_log_communication_to_known_bad_ip

  tags = {
    service = "aws_vpc_flow_logs",
    plugin  = "aws"
  }
}

query "vpc_flow_log_communication_to_known_bad_ip" {
  sql = <<-EOQ
    with known_bad_ips as (
      select ip, category from (
        values
          ('185.159.151.58', 'Command and Control'),
          ('91.132.255.89', 'Malware Distribution'),
          ('202.61.192.133', 'Cryptomining'),
          ('45.95.11.34', 'Ransomware'),
          ('164.68.121.45', 'Data Exfiltration')
      ) as bad_ips(ip, category)
    )
    
    select
      f.tp_id as id,
      f.tp_timestamp as time,
      'Communication with ' || b.category || ' IP' as title,
      case
        when b.category in ('Command and Control', 'Ransomware', 'Data Exfiltration') then 'critical'
        else 'high'
      end as severity,
      f.src_addr as source_ip,
      f.dst_addr as destination_ip,
      f.dst_port as destination_port,
      b.category as threat_category,
      case 
        when f.dst_addr = b.ip then 'Outbound to threat'
        when f.src_addr = b.ip then 'Inbound from threat'
        else 'Unknown'
      end as direction,
      f.protocol,
      f.bytes,
      f.region,
      f.account_id
    from
      aws_vpc_flow_log f
      join known_bad_ips b on f.dst_addr = b.ip or f.src_addr = b.ip
    where
      f.tp_timestamp >= dateadd(day, -7, current_timestamp)
      and f.action = 'ACCEPT'
    order by
      f.tp_timestamp desc
    limit 100
  EOQ
}

detection "vpc_flow_log_unusual_protocol_usage" {
  title       = "Unusual Protocol Usage"
  description = "Identifies the use of unusual or rarely used protocols that may indicate tunneling or covert channels."
  severity    = "medium"
  query       = query.vpc_flow_log_unusual_protocol_usage

  tags = {
    service = "aws_vpc_flow_logs",
    plugin  = "aws"
  }
}

query "vpc_flow_log_unusual_protocol_usage" {
  sql = <<-EOQ
    with common_protocols as (
      select protocol from (
        values
          (6),   -- TCP
          (17),  -- UDP
          (1)    -- ICMP
      ) as common_protos(protocol)
    )
    
    select
      f.tp_id as id,
      f.tp_timestamp as time,
      'Unusual Protocol Usage: Protocol ' || f.protocol as title,
      case
        when f.protocol in (41, 47, 50) then 'high'  -- Known tunneling protocols (IPv6, GRE, ESP)
        else 'medium'
      end as severity,
      f.src_addr as source_ip,
      f.dst_addr as destination_ip,
      f.protocol,
      case 
        when f.protocol = 41 then 'IPv6 encapsulation'
        when f.protocol = 47 then 'GRE'
        when f.protocol = 50 then 'ESP'
        when f.protocol = 51 then 'AH'
        else 'Protocol ' || f.protocol
      end as protocol_name,
      f.bytes,
      f.region,
      f.account_id
    from
      aws_vpc_flow_log f
    where
      f.tp_timestamp >= dateadd(day, -1, current_timestamp)
      and f.protocol not in (select protocol from common_protocols)
      and f.action = 'ACCEPT'
    order by
      f.tp_timestamp desc
    limit 100
  EOQ
}

detection "vpc_flow_log_unidirectional_traffic_flow" {
  title       = "Unidirectional Traffic Flow"
  description = "Identifies instances where traffic is only flowing in one direction, which may indicate data exfiltration or misconfigurations."
  severity    = "medium"
  query       = query.vpc_flow_log_unidirectional_traffic_flow

  tags = {
    service = "aws_vpc_flow_logs",
    plugin  = "aws"
  }
}

query "vpc_flow_log_unidirectional_traffic_flow" {
  sql = <<-EOQ
    with traffic_flows as (
      select
        f.src_addr,
        f.dst_addr,
        sum(case when f.src_addr < f.dst_addr then f.bytes else 0 end) as forward_bytes,
        sum(case when f.src_addr > f.dst_addr then f.bytes else 0 end) as reverse_bytes
      from
        aws_vpc_flow_log f
      where
        f.tp_timestamp >= dateadd(hour, -6, current_timestamp)
        and f.action = 'ACCEPT'
      group by
        f.src_addr,
        f.dst_addr
      having
        (
          (sum(case when f.src_addr < f.dst_addr then f.bytes else 0 end) > 1000000 and sum(case when f.src_addr > f.dst_addr then f.bytes else 0 end) = 0)
          or
          (sum(case when f.src_addr > f.dst_addr then f.bytes else 0 end) > 1000000 and sum(case when f.src_addr < f.dst_addr then f.bytes else 0 end) = 0)
        )
    )
    
    select
      f.tp_id as id,
      f.tp_timestamp as time,
      'Unidirectional Traffic Flow' as title,
      case
        when (tf.forward_bytes > 0 and tf.forward_bytes > 100000000) or (tf.reverse_bytes > 0 and tf.reverse_bytes > 100000000) then 'high'
        else 'medium'
      end as severity,
      tf.src_addr as source_ip,
      tf.dst_addr as destination_ip,
      case when tf.forward_bytes > 0 then tf.forward_bytes else tf.reverse_bytes end as bytes,
      round(case when tf.forward_bytes > 0 then tf.forward_bytes else tf.reverse_bytes end / 1024 / 1024, 2) as total_mb,
      case when tf.forward_bytes > 0 then 'Forward' else 'Reverse' end as direction,
      f.protocol,
      f.region,
      f.account_id
    from
      traffic_flows tf
      join aws_vpc_flow_log f on tf.src_addr = f.src_addr and tf.dst_addr = f.dst_addr
    order by
      case when tf.forward_bytes > 0 then tf.forward_bytes else tf.reverse_bytes end desc
    limit 100
  EOQ
}

