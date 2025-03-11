dashboard "vpc_flow_log_ip_sankey" {
  title = "VPC Flow Log IP Traffic Analysis"

  input "source_ip" {
    title = "Select a source IP address:"
    query = query.vpc_flow_log_source_ip_input
    width = 4
  }

  flow {
    title = "Traffic Flow from From Source IP"
    query = query.vpc_flow_log_ip_specific_sankey
    args  = [self.input.source_ip.value]
    width = 12
    type  = "sankey"
    
    category "srcaddr" {
      color = "blue"
    }
    
    category "flow_direction" {
      color = "green"
    }
    
    category "application" {
      color = "orange"
    }
    
    category "dstaddr" {
      color = "red"
    }
  }
  
  table {
    title = "Traffic Details for From Source IP"
    query = query.vpc_flow_log_ip_traffic_details
    args  = [self.input.source_ip.value]
    width = 12
  }
}

query "vpc_flow_log_ip_specific_sankey" {
  sql = <<-EOQ
    with flow_data as (
      select
        src_addr,
        flow_direction,
        case
          when dst_port = 80 then 'http'
          when dst_port = 443 then 'https'
          when dst_port = 22 then 'ssh'
          when dst_port = 3389 then 'rdp'
          when dst_port = 53 then 'dns'
          when dst_port between 1024 and 49151 then 'registered-port-' || dst_port::text
          when dst_port > 49151 then 'ephemeral-port'
          else 'port-' || dst_port::text
        end as application,
        dst_addr,
        sum(bytes) as total_bytes
      from
        aws_vpc_flow_log
      where
        src_addr = $1
        and dst_addr is not null
        and flow_direction is not null
      group by
        src_addr, flow_direction, application, dst_addr
      order by
        total_bytes desc
      limit 100
    ),
    
    -- Source IP to Flow Direction
    level1 as (
      select
        'srcaddr' as from_category,
        'flow_direction' as to_category,
        src_addr as from_id,
        flow_direction as to_id,
        sum(total_bytes) as value
      from
        flow_data
      group by
        src_addr, flow_direction
    ),
    
    -- Flow Direction to Application
    level2 as (
      select
        'flow_direction' as from_category,
        'application' as to_category,
        flow_direction as from_id,
        application as to_id,
        sum(total_bytes) as value
      from
        flow_data
      group by
        flow_direction, application
    ),
    
    -- Application to Destination
    level3 as (
      select
        'application' as from_category,
        'dstaddr' as to_category,
        application as from_id,
        dst_addr as to_id,
        sum(total_bytes) as value
      from
        flow_data
      group by
        application, dst_addr
    )
    
    -- Combine all levels
    select * from level1
    union all
    select * from level2
    union all
    select * from level3
    order by value desc
  EOQ
}

query "vpc_flow_log_ip_traffic_details" {
  sql = <<-EOQ
    select
      dst_addr as "Destination IP",
      flow_direction as "Flow Direction",
      dst_port as "Destination Port",
      case
        when dst_port = 80 then 'HTTP'
        when dst_port = 443 then 'HTTPS'
        when dst_port = 22 then 'SSH'
        when dst_port = 3389 then 'RDP'
        when dst_port = 53 then 'DNS'
        else 'Other'
      end as "Service",
      count(*) as "Connection Count",
      sum(bytes) as "Total Bytes",
      sum(packets) as "Total Packets",
      max(start_time) as "Last Seen"
    from
      aws_vpc_flow_log
    where
      src_addr = $1
    group by
      dst_addr, flow_direction, dst_port
    order by
      "Total Bytes" desc
    limit 50;
  EOQ
}