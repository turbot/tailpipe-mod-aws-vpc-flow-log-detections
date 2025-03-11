dashboard "vpc_flow_log_ip_conversations" {
  title         = "VPC Flow Log IP-Centered Conversations"
  documentation = "Visualizes VPC Flow Log traffic patterns starting from IP addresses across multiple dimensions."

  tags = {
    service = "AWS/VPC"
    type    = "Dashboard"
  }

  text {
    value = "Displaying VPC flow log traffic patterns with source IP as the entry point"
    width = 12
  }

  flow {
    title = "Network Traffic by Source IP"
    query = query.vpc_flow_log_ip_entry_conversations
    width = 12
    type  = "sankey"
    
    category "srcaddr" {
      color = "blue"
    }
    
    category "flow_direction" {
      color = "orange"
    }
    
    category "application" {
      color = "red" 
    }
    
    category "traffic_path_desc" {
      color = "purple"
    }
    
    category "region" {
      color = "green"
    }
  }
}

query "vpc_flow_log_ip_entry_conversations" {
  sql = <<-EOQ
    with filtered_logs as (
      select 
        src_addr,
        flow_direction,
        case
          when dst_port = 80 then 'http'
          when dst_port = 443 then 'https'
          when dst_port = 3389 then 'rdp'
          when dst_port = 22 then 'ssh'
          when dst_port = 53 then 'dns'
          when dst_port in (8080, 8443) then 'web-alt'
          else 'other'
        end as application,
        case
          when pkt_dst_aws_service is not null then pkt_dst_aws_service
          when traffic_path = 1 then 'INGRESS_THROUGH_IGW'
          when traffic_path = 2 then 'EGRESS_THROUGH_IGW'
          when traffic_path = 3 then 'INTRA_VPC'
          when traffic_path = 4 then 'INGRESS_THROUGH_VPN'
          when traffic_path = 5 then 'EGRESS_THROUGH_VPN'
          when traffic_path = 6 then 'INGRESS_THROUGH_TGW'
          when traffic_path = 7 then 'EGRESS_THROUGH_TGW'
          when traffic_path = 8 then 'INGRESS_THROUGH_LOCAL_ZONE'
          when traffic_path = 9 then 'EGRESS_THROUGH_LOCAL_ZONE'
          else 'UNKNOWN'
        end as traffic_path_desc,
        region,
        sum(bytes) as total_bytes
      from 
        aws_vpc_flow_log
      where 
        src_addr is not null
      group by
        src_addr, flow_direction, application, traffic_path_desc, region
      order by
        total_bytes desc
      limit 100
    ),
    
    -- First level: Source IP to Flow Direction
    level1 as (
      select
        'srcaddr' as from_category,
        'flow_direction' as to_category,
        src_addr as from_id,
        flow_direction as to_id,
        sum(total_bytes) as value
      from 
        filtered_logs
      group by
        src_addr, flow_direction
    ),
    
    -- Second level: Flow Direction to Application
    level2 as (
      select
        'flow_direction' as from_category,
        'application' as to_category,
        flow_direction as from_id,
        application as to_id,
        sum(total_bytes) as value
      from 
        filtered_logs
      group by
        flow_direction, application
    ),
    
    -- Third level: Application to Traffic Path Description
    level3 as (
      select
        'application' as from_category,
        'traffic_path_desc' as to_category,
        application as from_id,
        traffic_path_desc as to_id,
        sum(total_bytes) as value
      from 
        filtered_logs
      group by
        application, traffic_path_desc
    ),
    
    -- Fourth level: Traffic Path to Region
    level4 as (
      select
        'traffic_path_desc' as from_category,
        'region' as to_category,
        traffic_path_desc as from_id,
        region as to_id,
        sum(total_bytes) as value
      from 
        filtered_logs
      group by
        traffic_path_desc, region
    )
    
    -- Combine all levels
    select * from level1
    union all
    select * from level2
    union all
    select * from level3
    union all
    select * from level4
    order by value desc
  EOQ
}