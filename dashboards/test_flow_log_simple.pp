dashboard "vpc_flow_log_network_with_resources" {
  title         = "VPC Flow Log Network Analysis with AWS Resources"
  documentation = "Visualizes VPC Flow Log data as a network graph showing traffic relationships between IPs and AWS resources."

  tags = {
    service = "AWS/VPC"
    type    = "Dashboard"
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
    title     = "Network Traffic Graph"
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
          src_addr is not null
          and dst_addr is not null
        group by 
          src_addr, dst_addr, instance_id, ecs_task_id, ecs_cluster_name
        having 
          sum(bytes) >= cast($1 as bigint)
        order by 
          total_bytes desc
        limit 500
      ),
      -- IP address nodes
      ip_nodes as (
        -- Source IP nodes
        select distinct 
          src_addr as id,
          src_addr as title,
          'ip_address' as category
        from 
          traffic_data
        
        union
        
        -- Destination IP nodes
        select distinct 
          dst_addr as id,
          dst_addr as title,
          'ip_address' as category
        from 
          traffic_data
      ),
      -- EC2 instance nodes
      ec2_nodes as (
        select distinct
          instance_id as id,
          instance_id as title,
          'ec2_instance' as category
        from
          traffic_data
        where
          instance_id is not null
      ),
      -- ECS task nodes
      ecs_task_nodes as (
        select distinct
          ecs_task_id as id,
          ecs_task_id as title,
          'ecs_task' as category
        from
          traffic_data
        where
          ecs_task_id is not null
      ),
      -- ECS cluster nodes
      ecs_cluster_nodes as (
        select distinct
          ecs_cluster_name as id,
          ecs_cluster_name as title,
          'ecs_cluster' as category
        from
          traffic_data
        where
          ecs_cluster_name is not null
      ),
      -- Combine all nodes
      all_nodes as (
        select * from ip_nodes
        union all
        select * from ec2_nodes
        union all
        select * from ecs_task_nodes
        union all
        select * from ecs_cluster_nodes
      ),
      -- IP to IP edges
      ip_edges as (
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
      ),
      -- IP to EC2 instance edges
      ec2_edges as (
        select
          src_addr as from_id,
          instance_id as to_id,
          'traffic to instance' as title
        from
          traffic_data
        where
          instance_id is not null
        group by
          src_addr, instance_id
      ),
      -- IP to ECS task edges
      ecs_task_edges as (
        select
          src_addr as from_id,
          ecs_task_id as to_id,
          'traffic to task' as title
        from
          traffic_data
        where
          ecs_task_id is not null
        group by
          src_addr, ecs_task_id
      ),
      -- IP to ECS cluster edges
      ecs_cluster_edges as (
        select
          src_addr as from_id,
          ecs_cluster_name as to_id,
          'traffic to cluster' as title
        from
          traffic_data
        where
          ecs_cluster_name is not null
        group by
          src_addr, ecs_cluster_name
      ),
      -- Combine all edges
      all_edges as (
        select * from ip_edges
        union all
        select * from ec2_edges
        union all
        select * from ecs_task_edges
        union all
        select * from ecs_cluster_edges
      )
      -- Combine nodes and edges with explicit selection of required fields
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
        all_edges.from_id,
        all_edges.to_id
      from
        all_edges;
    EOQ
    args = [self.input.min_traffic.value]
  }

  table {
    title = "AWS Resources in Traffic Flows"
    sql   = <<-EOQ
      select
        src_addr as "Source IP",
        dst_addr as "Destination IP",
        instance_id as "EC2 Instance",
        ecs_task_id as "ECS Task",
        ecs_cluster_name as "ECS Cluster",
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
        (instance_id is not null or ecs_task_id is not null or ecs_cluster_name is not null)
        and src_addr is not null
        and dst_addr is not null
      group by
        src_addr, dst_addr, instance_id, ecs_task_id, ecs_cluster_name
      having
        sum(bytes) >= cast($1 as bigint)
      order by
        sum(bytes) desc
      limit 50;
    EOQ
    args = [self.input.min_traffic.value]
    width = 12
  }

  table {
    title = "Top IP Traffic Flows"
    sql   = <<-EOQ
      select
        src_addr as "Source IP",
        dst_addr as "Destination IP",
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
        src_addr is not null
        and dst_addr is not null
      group by
        src_addr, dst_addr
      having
        sum(bytes) >= cast($1 as bigint)
      order by
        sum(bytes) desc
      limit 50;
    EOQ
    args = [self.input.min_traffic.value]
    width = 12
  }
}