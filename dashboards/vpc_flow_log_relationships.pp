dashboard "vpc_flow_log_source_ip_sankey" {
  title         = "VPC Flow Log Source IP Sankey Analysis"
  documentation = "Visualizes VPC Flow Log traffic patterns starting from a specific source IP address using a Sankey diagram."

  tags = {
    service = "AWS/VPC"
    type    = "Dashboard"
  }

  # Source IP address input to filter the flow logs
  input "source_ip" {
    title = "Select a source IP address:"
    query = query.vpc_flow_log_source_ip_input
    width = 4
  }

  container {
    card {
      title = "Total Traffic Volume"
      query = query.vpc_flow_log_total_bytes
      width = 3
      args  = [self.input.source_ip.value]
    }

    card {
      title = "Unique Destinations"
      query = query.vpc_flow_log_unique_destinations
      width = 3
      args  = [self.input.source_ip.value]
    }

    card {
      title = "Traffic Acceptance Rate"
      query = query.vpc_flow_log_acceptance_rate
      width = 3
      args  = [self.input.source_ip.value]
    }

    card {
      title = "Unique Services Accessed"
      query = query.vpc_flow_log_unique_services
      width = 3
      args  = [self.input.source_ip.value]
    }
  }

  # Sankey diagram showing traffic flow from source IP to destinations and on to services/ports
  flow {
    title = "Traffic Flow from Source IP"
    width = 12
    type  = "sankey"
    query = query.vpc_flow_log_sankey_flows
    args  = [self.input.source_ip.value]

    category "source_ip" {
      color = "ok"
    }

    category "destination_ip" {
      color = "info"
    }
    
    category "port" {
      color = "warning"
    }
    
    category "service" {
      color = "alert"
    }
    
    category "vpc" {
      color = "purple"
    }
    
    category "protocol" {
      color = "blue"
    }
  }
}

query "vpc_flow_log_source_ip_input" {
  sql = <<-EOQ
    select distinct
      src_addr as value,
      src_addr as label,
      sum(bytes) as total_bytes
    from
      aws_vpc_flow_log
    where
      src_addr is not null
    group by
      src_addr
    order by
      total_bytes desc
    limit 10;
  EOQ
}

query "vpc_flow_log_total_bytes" {
  sql = <<-EOQ
    select
      sum(bytes) as value,
      case
        when sum(bytes) > 1073741824 then 'GB'
        when sum(bytes) > 1048576 then 'MB'
        when sum(bytes) > 1024 then 'KB'
        else 'Bytes'
      end as unit
    from
      aws_vpc_flow_log
    where
      src_addr = $1;
  EOQ
}

query "vpc_flow_log_unique_destinations" {
  sql = <<-EOQ
    select
      count(distinct dst_addr) as value
    from
      aws_vpc_flow_log
    where
      src_addr = $1;
  EOQ
}

query "vpc_flow_log_acceptance_rate" {
  sql = <<-EOQ
    with flow_stats as (
      select
        count(*) as total_flows,
        count(*) filter (where action = 'ACCEPT') as accepted_flows
      from
        aws_vpc_flow_log
      where
        src_addr = $1
    )
    select
      case
        when total_flows = 0 then 0
        else round(100.0 * accepted_flows / total_flows, 1)
      end as value,
      '%' as unit,
      case
        when (100.0 * accepted_flows / total_flows) < 50 then 'alert'
        when (100.0 * accepted_flows / total_flows) < 80 then 'warning'
        else 'ok'
      end as type
    from
      flow_stats;
  EOQ
}

query "vpc_flow_log_unique_services" {
  sql = <<-EOQ
    select
      count(distinct pkt_dst_aws_service) as value
    from
      aws_vpc_flow_log
    where
      src_addr = $1
      and pkt_dst_aws_service is not null;
  EOQ
}

query "vpc_flow_log_sankey_flows" {
  sql = <<-EOQ
    -- First level: Source IP to Destination IPs
    select
      'source_ip' as from_category,
      'destination_ip' as to_category, 
      src_addr as from_id,
      dst_addr as to_id,
      sum(bytes) as value
    from
      aws_vpc_flow_log
    where
      src_addr = $1
      and dst_addr is not null
    group by
      src_addr, dst_addr
    
    union all
    
    -- Second level: Destination IPs to Destination Ports
    select
      'destination_ip' as from_category,
      'port' as to_category,
      dst_addr as from_id,
      case
        when dst_port = 22 then 'SSH (22)'
        when dst_port = 80 then 'HTTP (80)'
        when dst_port = 443 then 'HTTPS (443)'
        when dst_port = 3389 then 'RDP (3389)'
        when dst_port = 1433 then 'MSSQL (1433)'
        when dst_port = 3306 then 'MySQL (3306)'
        when dst_port = 5432 then 'PostgreSQL (5432)'
        else 'Port ' || dst_port::text
      end as to_id,
      sum(bytes) as value
    from
      aws_vpc_flow_log
    where
      src_addr = $1
      and dst_addr is not null
      and dst_port is not null
    group by
      dst_addr, dst_port
    
    union all
    
    -- Third level: Destination IPs to AWS Services (if applicable)
    select
      'destination_ip' as from_category,
      'service' as to_category,
      dst_addr as from_id,
      pkt_dst_aws_service as to_id,
      sum(bytes) as value
    from
      aws_vpc_flow_log
    where
      src_addr = $1
      and dst_addr is not null
      and pkt_dst_aws_service is not null
    group by
      dst_addr, pkt_dst_aws_service
    
    union all
    
    -- Fourth level: Destination IPs to VPC IDs
    select
      'destination_ip' as from_category,
      'vpc' as to_category,
      dst_addr as from_id,
      vpc_id as to_id,
      sum(bytes) as value
    from
      aws_vpc_flow_log
    where
      src_addr = $1
      and dst_addr is not null
      and vpc_id is not null
    group by
      dst_addr, vpc_id
    
    union all
    
    -- Fifth level: Source IP directly to Protocol
    select
      'source_ip' as from_category,
      'protocol' as to_category,
      src_addr as from_id,
      case
        when protocol = 1 then 'ICMP'
        when protocol = 6 then 'TCP'
        when protocol = 17 then 'UDP'
        else 'Protocol ' || protocol::text
      end as to_id,
      sum(bytes) as value
    from
      aws_vpc_flow_log
    where
      src_addr = $1
      and protocol is not null
    group by
      src_addr, protocol    
    order by
      value desc;
  EOQ
}