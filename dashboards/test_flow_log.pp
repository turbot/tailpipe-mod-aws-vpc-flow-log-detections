dashboard "vpc_flow_log_sankey_combined" {
  title = "VPC Flow Log Comprehensive Analysis"

  input "source_ip" {
    title = "Select a source IP address:"
    sql = <<-EOQ
      select distinct
        src_addr as value,
        src_addr as label
      from
        aws_vpc_flow_log
      where
        src_addr is not null
      order by
        src_addr
      limit 10;
    EOQ
    width = 4
  }

  flow {
    type  = "sankey"
    title = "Comprehensive Traffic Flow from Source IP"
    sql = <<-EOQ
      -- Source IP to Protocol
      select
        'srcaddr' as from_category,
        'protocol' as to_category,
        $1 as from_id,
        case
          when protocol = 6 then 'TCP'
          when protocol = 17 then 'UDP'
          when protocol = 1 then 'ICMP'
          else 'Other_' || coalesce(protocol::text, 'unknown')
        end as to_id,
        sum(bytes) as value
      from
        aws_vpc_flow_log
      where
        src_addr = $1
      group by
        protocol
      
      union all
      
      -- Protocol to Action
      select
        'protocol' as from_category,
        'action' as to_category,
        case
          when protocol = 6 then 'TCP'
          when protocol = 17 then 'UDP'
          when protocol = 1 then 'ICMP'
          else 'Other_' || coalesce(protocol::text, 'unknown')
        end as from_id,
        coalesce(action, 'unknown') as to_id,
        sum(bytes) as value
      from
        aws_vpc_flow_log
      where
        src_addr = $1
      group by
        protocol, action
      
      union all
      
      -- Action to Destination IP
      select
        'action' as from_category,
        'dstaddr' as to_category,
        coalesce(action, 'unknown') as from_id,
        dst_addr as to_id,
        sum(bytes) as value
      from
        aws_vpc_flow_log
      where
        src_addr = $1
        and dst_addr is not null
      group by
        action, dst_addr
      
      union all
      
      -- Destination IP to Port
      select
        'dstaddr' as from_category,
        'port' as to_category,
        dst_addr as from_id,
        'Port ' || dst_port::text as to_id,
        sum(bytes) as value
      from
        aws_vpc_flow_log
      where
        src_addr = $1
        and dst_addr is not null
        and dst_port is not null
      group by
        dst_addr, dst_port
      
      order by value desc
      limit 100
    EOQ
    args = [self.input.source_ip.value]
    
    category "srcaddr" {
      color = "blue"
    }
    
    category "protocol" {
      color = "purple"
    }
    
    category "action" {
      color = "green"
    }
    
    category "dstaddr" {
      color = "orange"
    }
    
    category "port" {
      color = "red"
    }
  }
  
  table {
    title = "Comprehensive Traffic Details"
    sql = <<-EOQ
      select
        case
          when protocol = 6 then 'TCP'
          when protocol = 17 then 'UDP'
          when protocol = 1 then 'ICMP'
          else 'Other_' || coalesce(protocol::text, 'unknown')
        end as "Protocol",
        coalesce(action, 'unknown') as "Action",
        dst_addr as "Destination IP",
        dst_port as "Destination Port",
        sum(bytes) as "Total Bytes",
        sum(packets) as "Total Packets"
      from
        aws_vpc_flow_log
      where
        src_addr = $1
      group by
        protocol, action, dst_addr, dst_port
      order by
        "Total Bytes" desc
      limit 15;
    EOQ
    args = [self.input.source_ip.value]
    width = 12
  }
}