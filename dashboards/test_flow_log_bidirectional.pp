dashboard "vpc_flow_log_nodes_with_bytes" {
  title         = "VPC Flow Log Network Analysis with Traffic Metrics"
  documentation = "Visualizes VPC flow logs as a network graph showing traffic volume in both nodes and edges."

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

  input "max_nodes" {
    title = "Maximum Nodes:"
    sql   = <<-EOQ
      select 
        '25' as label, 
        '25' as value
      union select 
        '50' as label, 
        '50' as value
      union select 
        '100' as label, 
        '100' as value
      union select 
        '200' as label, 
        '200' as value
      union select 
        '500' as label, 
        '500' as value
      order by value;
    EOQ
    width = 2
  }

  graph {
    title     = "Network Traffic Graph"
    type      = "graph"
    direction = "LR"
    sql = <<-EOQ
      -- Collect traffic data for all nodes
      with node_traffic as (
        -- Traffic for source IPs
        select
          src_addr as node_id,
          count(*) as flow_count,
          sum(bytes) as total_bytes_out,
          0 as total_bytes_in,
          sum(bytes) as total_bytes
        from
          aws_vpc_flow_log
        where
          src_addr is not null
        group by
          src_addr
          
        union all
        
        -- Traffic for destination IPs
        select
          dst_addr as node_id,
          count(*) as flow_count,
          0 as total_bytes_out,
          sum(bytes) as total_bytes_in,
          sum(bytes) as total_bytes
        from
          aws_vpc_flow_log
        where
          dst_addr is not null
        group by
          dst_addr
      ),
      
      -- Aggregate node traffic
      combined_node_traffic as (
        select
          node_id,
          sum(flow_count) as flow_count,
          sum(total_bytes_out) as total_bytes_out,
          sum(total_bytes_in) as total_bytes_in,
          sum(total_bytes) as total_bytes
        from
          node_traffic
        group by
          node_id
        having 
          sum(total_bytes) >= cast($1 as bigint)
        order by
          total_bytes desc
        limit cast($2 as integer)
      ),
      
      -- Collect bidirectional traffic data for edges
      bidirectional_traffic as (
        -- Traffic from source to destination
        select
          src_addr as node1,
          dst_addr as node2,
          count(*) as flow_count,
          sum(bytes) as bytes,
          interface_id,
          ecs_task_id,
          ecs_cluster_name
        from
          aws_vpc_flow_log
        where
          src_addr in (select node_id from combined_node_traffic)
          and dst_addr in (select node_id from combined_node_traffic)
        group by
          src_addr, dst_addr, interface_id, ecs_task_id, ecs_cluster_name
          
        union all
        
        -- Traffic from destination to source
        select
          dst_addr as node1,
          src_addr as node2,
          count(*) as flow_count,
          sum(bytes) as bytes,
          interface_id,
          ecs_task_id,
          ecs_cluster_name
        from
          aws_vpc_flow_log
        where
          src_addr in (select node_id from combined_node_traffic)
          and dst_addr in (select node_id from combined_node_traffic)
        group by
          dst_addr, src_addr, interface_id, ecs_task_id, ecs_cluster_name
      ),
      
      -- Aggregate bidirectional traffic
      combined_traffic as (
        select
          node1,
          node2,
          sum(flow_count) as flow_count,
          sum(bytes) as total_bytes,
          -- Take any non-null resource IDs
          max(interface_id) as interface_id,
          max(ecs_task_id) as ecs_task_id,
          max(ecs_cluster_name) as ecs_cluster_name
        from
          bidirectional_traffic
        group by
          node1, node2
        having
          sum(bytes) >= cast($1 as bigint)
        order by
          total_bytes desc
      ),
      
      -- Collect other resources
      resources as (
        select distinct
          interface_id,
          ecs_task_id,
          ecs_cluster_name,
          sum(bytes) as total_bytes
        from
          aws_vpc_flow_log
        where
          (interface_id is not null or ecs_task_id is not null or ecs_cluster_name is not null)
          and (
            src_addr in (select node_id from combined_node_traffic)
            or dst_addr in (select node_id from combined_node_traffic)
          )
        group by
          interface_id, ecs_task_id, ecs_cluster_name
        having
          sum(bytes) >= cast($1 as bigint)
      ),
      
      -- Create IP Nodes with traffic metrics
      ip_nodes as (
        select
          cnt.node_id as id,
          -- Include traffic metrics in node title
          cnt.node_id || ' (' || 
            case 
              when cnt.total_bytes > 1048576 then round(cast(cnt.total_bytes as numeric) / 1048576, 2) || ' MB' 
              when cnt.total_bytes > 1024 then round(cast(cnt.total_bytes as numeric) / 1024, 2) || ' KB'
              else cnt.total_bytes || ' B'
            end || 
            ', ' || cnt.flow_count || ' flows)' as title,
          'ip_address' as category,
          json_object(
            'total_bytes', cnt.total_bytes,
            'bytes_in', cnt.total_bytes_in,
            'bytes_out', cnt.total_bytes_out,
            'flow_count', cnt.flow_count
          ) as properties
        from
          combined_node_traffic cnt
      ),
      
      -- Create ENI nodes
      eni_nodes as (
        select distinct
          interface_id as id,
          interface_id || ' (' || 
            case 
              when total_bytes > 1048576 then round(cast(total_bytes as numeric) / 1048576, 2) || ' MB' 
              when total_bytes > 1024 then round(cast(total_bytes as numeric) / 1024, 2) || ' KB'
              else total_bytes || ' B'
            end || ')' as title,
          'eni' as category,
          json_object(
            'total_bytes', total_bytes
          ) as properties
        from
          resources
        where
          interface_id is not null
      ),
      
      -- Create ECS task nodes
      ecs_task_nodes as (
        select distinct
          ecs_task_id as id,
          ecs_task_id || ' (' || 
            case 
              when total_bytes > 1048576 then round(cast(total_bytes as numeric) / 1048576, 2) || ' MB' 
              when total_bytes > 1024 then round(cast(total_bytes as numeric) / 1024, 2) || ' KB'
              else total_bytes || ' B'
            end || ')' as title,
          'ecs_task' as category,
          json_object(
            'total_bytes', total_bytes
          ) as properties
        from
          resources
        where
          ecs_task_id is not null
      ),
      
      -- Create ECS cluster nodes
      ecs_cluster_nodes as (
        select distinct
          ecs_cluster_name as id,
          ecs_cluster_name || ' (' || 
            case 
              when total_bytes > 1048576 then round(cast(total_bytes as numeric) / 1048576, 2) || ' MB' 
              when total_bytes > 1024 then round(cast(total_bytes as numeric) / 1024, 2) || ' KB'
              else total_bytes || ' B'
            end || ')' as title,
          'ecs_cluster' as category,
          json_object(
            'total_bytes', total_bytes
          ) as properties
        from
          resources
        where
          ecs_cluster_name is not null
      ),
      
      -- Combine all nodes
      all_nodes as (
        select * from ip_nodes
        union all
        select * from eni_nodes
        union all
        select * from ecs_task_nodes
        union all
        select * from ecs_cluster_nodes
      ),
      
      -- Create IP-to-IP edges with bidirectional traffic counts
      ip_ip_edges as (
        select
          node1 as from_id,
          node2 as to_id,
          flow_count || ' flows, ' || 
          case 
            when total_bytes > 1048576 then round(cast(total_bytes as numeric) / 1048576, 2) || ' MB' 
            when total_bytes > 1024 then round(cast(total_bytes as numeric) / 1024, 2) || ' KB'
            else total_bytes || ' B'
          end as title
        from
          combined_traffic
        where
          node1 in (select id from ip_nodes)
          and node2 in (select id from ip_nodes)
      ),
      
      -- Create IP-to-ENI edges
      ip_eni_edges as (
        select distinct
          ct.node1 as from_id,
          ct.interface_id as to_id,
          'via ' || 
          case 
            when ct.total_bytes > 1048576 then round(cast(ct.total_bytes as numeric) / 1048576, 2) || ' MB' 
            when ct.total_bytes > 1024 then round(cast(ct.total_bytes as numeric) / 1024, 2) || ' KB'
            else ct.total_bytes || ' B'
          end as title
        from
          combined_traffic ct
        where
          ct.interface_id is not null
          and ct.node1 in (select id from ip_nodes)
      ),
      
      -- Create ENI-to-ECS task edges
      eni_task_edges as (
        select distinct
          r.interface_id as from_id,
          r.ecs_task_id as to_id,
          'attached to' as title
        from
          resources r
        where
          r.interface_id is not null
          and r.ecs_task_id is not null
      ),
      
      -- Create ECS task-to-cluster edges
      task_cluster_edges as (
        select distinct
          r.ecs_task_id as from_id,
          r.ecs_cluster_name as to_id,
          'in cluster' as title
        from
          resources r
        where
          r.ecs_task_id is not null
          and r.ecs_cluster_name is not null
      ),
      
      -- Combine all edges
      all_edges as (
        select * from ip_ip_edges
        union all
        select * from ip_eni_edges
        union all
        select * from eni_task_edges
        union all
        select * from task_cluster_edges
      )
      
      -- Combine nodes and edges
      select
        all_nodes.id,
        all_nodes.title,
        all_nodes.category,
        all_nodes.properties,
        null as from_id,
        null as to_id
      from
        all_nodes
      
      union all
      
      select
        null as id,
        null as title,
        null as category,
        null as properties,
        all_edges.from_id,
        all_edges.to_id
      from
        all_edges
      where
        exists (select 1 from all_nodes where all_nodes.id = all_edges.from_id)
        and exists (select 1 from all_nodes where all_nodes.id = all_edges.to_id);
    EOQ
    args = [self.input.min_traffic.value, self.input.max_nodes.value]
  }

  table {
    title = "Top Nodes by Traffic Volume"
    sql   = <<-EOQ
      with node_traffic as (
        -- Traffic for source IPs
        select
          src_addr as node_id,
          'Source' as direction,
          count(*) as flow_count,
          sum(bytes) as total_bytes
        from
          aws_vpc_flow_log
        where
          src_addr is not null
        group by
          src_addr
          
        union all
        
        -- Traffic for destination IPs
        select
          dst_addr as node_id,
          'Destination' as direction,
          count(*) as flow_count,
          sum(bytes) as total_bytes
        from
          aws_vpc_flow_log
        where
          dst_addr is not null
        group by
          dst_addr
      ),
      
      -- Aggregate node traffic
      combined_node_traffic as (
        select
          node_id as "Node",
          sum(flow_count) as "Flow Count",
          sum(total_bytes) as "Total Bytes",
          string_agg(distinct direction, ', ') as "Direction",
          case 
            when sum(total_bytes) > 1073741824 then round(cast(sum(total_bytes) as numeric) / 1073741824, 2) || ' GB'
            when sum(total_bytes) > 1048576 then round(cast(sum(total_bytes) as numeric) / 1048576, 2) || ' MB' 
            when sum(total_bytes) > 1024 then round(cast(sum(total_bytes) as numeric) / 1024, 2) || ' KB'
            else sum(total_bytes) || ' B'
          end as "Formatted Size"
        from
          node_traffic
        group by
          node_id
        having 
          sum(total_bytes) >= cast($1 as bigint)
        order by
          "Total Bytes" desc
        limit 50
      )
      
      select * from combined_node_traffic;
    EOQ
    args = [self.input.min_traffic.value]
    width = 12
  }

  table {
    title = "Top Traffic Relationships"
    sql   = <<-EOQ
      with bidirectional_traffic as (
        -- Traffic from source to destination
        select
          src_addr as node1,
          dst_addr as node2,
          count(*) as flow_count,
          sum(bytes) as bytes
        from
          aws_vpc_flow_log
        where
          src_addr is not null
          and dst_addr is not null
        group by
          src_addr, dst_addr
          
        union all
        
        -- Traffic from destination to source
        select
          dst_addr as node1,
          src_addr as node2,
          count(*) as flow_count,
          sum(bytes) as bytes
        from
          aws_vpc_flow_log
        where
          src_addr is not null
          and dst_addr is not null
        group by
          dst_addr, src_addr
      ),
      
      -- Aggregate bidirectional traffic
      combined_traffic as (
        select
          node1 as "IP Address 1",
          node2 as "IP Address 2",
          sum(flow_count) as "Flow Count",
          sum(bytes) as "Total Bytes",
          case 
            when sum(bytes) > 1073741824 then round(cast(sum(bytes) as numeric) / 1073741824, 2) || ' GB'
            when sum(bytes) > 1048576 then round(cast(sum(bytes) as numeric) / 1048576, 2) || ' MB' 
            when sum(bytes) > 1024 then round(cast(sum(bytes) as numeric) / 1024, 2) || ' KB'
            else sum(bytes) || ' B'
          end as "Formatted Size"
        from
          bidirectional_traffic
        group by
          node1, node2
        having
          sum(bytes) >= cast($1 as bigint)
        order by
          "Total Bytes" desc
        limit 50
      )
      
      select * from combined_traffic;
    EOQ
    args = [self.input.min_traffic.value]
    width = 12
  }
}