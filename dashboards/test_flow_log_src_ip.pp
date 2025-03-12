dashboard "vpc_flow_log_source_ip_network" {
  title         = "VPC Flow Log Source IP Network Analysis"
  documentation = "Visualizes network traffic from a specific source IP address to its destinations and related AWS resources."

  tags = {
    service = "AWS/VPC"
    type    = "Dashboard"
  }

  input "source_ip" {
    title = "Select a source IP address:"
    sql   = <<-EOQ
      select distinct
        src_addr as value,
        src_addr as label
      from
        aws_vpc_flow_log
      where
        src_addr is not null
      order by
        src_addr
      limit 1000;
    EOQ
    width = 4
  }

  input "min_traffic" {
    title = "Minimum Traffic (bytes):"
    sql   = <<-EOQ
      select 
        '0' as label, 
        '0' as value
      union select 
        '1 KB' as label, 
        '1024' as value
      union select 
        '10 KB' as label, 
        '10240' as value
      union select 
        '100 KB' as label, 
        '102400' as value
      union select 
        '1 MB' as label, 
        '1048576' as value
      order by value;
    EOQ
    width = 2
  }

  graph {
    title     = "Network Traffic from Source IP"
    type      = "graph"
    direction = "LR"
    sql = <<-EOQ
      with traffic_data as (
        select 
          src_addr,
          dst_addr,
          instance_id,
          ecs_task_id,
          ecs_cluster_name,
          sum(bytes) as total_bytes,
          count(*) as connection_count
        from 
          aws_vpc_flow_log
        where
          src_addr = $1
          and dst_addr is not null
        group by 
          src_addr, dst_addr, instance_id, ecs_task_id, ecs_cluster_name
        having 
          sum(bytes) >= cast($2 as bigint)
        order by 
          total_bytes desc
        limit 500
      ),
      -- IP address nodes
      ip_nodes as (
        -- Source IP
        select distinct 
          src_addr as id,
          src_addr as title,
          'source_ip' as category
        from 
          traffic_data
        
        union
        
        -- Destination IPs
        select distinct 
          dst_addr as id,
          dst_addr as title,
          'destination_ip' as category
        from 
          traffic_data
      ),
      -- Resource nodes
      resource_nodes as (
        -- EC2 instances
        select distinct
          instance_id as id,
          instance_id as title,
          'ec2_instance' as category
        from
          traffic_data
        where
          instance_id is not null
          
        union all
        
        -- ECS tasks
        select distinct
          ecs_task_id as id,
          ecs_task_id as title,
          'ecs_task' as category
        from
          traffic_data
        where
          ecs_task_id is not null
          
        union all
        
        -- ECS clusters
        select distinct
          ecs_cluster_name as id,
          ecs_cluster_name as title,
          'ecs_cluster' as category
        from
          traffic_data
        where
          ecs_cluster_name is not null
      ),
      -- All nodes
      all_nodes as (
        select * from ip_nodes
        union all
        select * from resource_nodes
      ),
      -- Traffic edges
      traffic_edges as (
        -- Source to destination edges
        select
          src_addr as from_id,
          dst_addr as to_id,
          count(*) || ' connections, ' || 
          case 
            when sum(total_bytes) > 1048576 then round(cast(sum(total_bytes) as numeric) / 1048576, 2) || ' MB' 
            when sum(total_bytes) > 1024 then round(cast(sum(total_bytes) as numeric) / 1024, 2) || ' KB'
            else sum(total_bytes) || ' B'
          end as title
        from
          traffic_data
        group by
          src_addr, dst_addr
          
        union all
        
        -- Destination to resource edges
        select
          dst_addr as from_id,
          instance_id as to_id,
          'associated with instance' as title
        from
          traffic_data
        where
          instance_id is not null
        group by
          dst_addr, instance_id
          
        union all
        
        select
          dst_addr as from_id,
          ecs_task_id as to_id,
          'associated with task' as title
        from
          traffic_data
        where
          ecs_task_id is not null
        group by
          dst_addr, ecs_task_id
          
        union all
        
        select
          dst_addr as from_id,
          ecs_cluster_name as to_id,
          'associated with cluster' as title
        from
          traffic_data
        where
          ecs_cluster_name is not null
        group by
          dst_addr, ecs_cluster_name
      )
      -- Combine nodes and edges
      select
        all_nodes.id,
        all_nodes.title,
        all_nodes.category,
        null as from_id,
        null as to_id
      from
        all_nodes
      
      union all
      
      select
        null as id,
        null as title,
        null as category,
        traffic_edges.from_id,
        traffic_edges.to_id
      from
        traffic_edges;
    EOQ
    args = [self.input.source_ip.value, self.input.min_traffic.value]
  }

  table {
    title = "Destination Details from Source IP"
    sql   = <<-EOQ
      select
        dst_addr as "Destination IP",
        case 
          when instance_id is not null then instance_id
          when ecs_task_id is not null then ecs_task_id
          when ecs_cluster_name is not null then ecs_cluster_name
          else 'None'
        end as "Associated Resource",
        case
          when instance_id is not null then 'EC2 Instance'
          when ecs_task_id is not null then 'ECS Task'
          when ecs_cluster_name is not null then 'ECS Cluster'
          else 'None'
        end as "Resource Type",
        dst_port as "Destination Port",
        action as "Action",
        count(*) as "Connection Count",
        sum(bytes) as "Total Bytes",
        case 
          when sum(bytes) > 1073741824 then round(cast(sum(bytes) as numeric) / 1073741824, 2) || ' GB'
          when sum(bytes) > 1048576 then round(cast(sum(bytes) as numeric) / 1048576, 2) || ' MB' 
          when sum(bytes) > 1024 then round(cast(sum(bytes) as numeric) / 1024, 2) || ' KB'
          else sum(bytes) || ' B'
        end as "Formatted Size"
      from
        aws_vpc_flow_log
      where
        src_addr = $1
        and dst_addr is not null
      group by
        dst_addr, instance_id, ecs_task_id, ecs_cluster_name, dst_port, action
      having
        sum(bytes) >= cast($2 as bigint)
      order by
        sum(bytes) desc
      limit 50;
    EOQ
    args = [self.input.source_ip.value, self.input.min_traffic.value]
    width = 12
  }
}