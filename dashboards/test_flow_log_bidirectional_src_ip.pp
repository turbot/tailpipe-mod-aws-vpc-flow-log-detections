dashboard "vpc_flow_log_complete_analysis" {
  title         = "VPC Flow Log Network Analysis"
  documentation = "Visualizes network traffic from a specific source IP, showing traffic metrics in nodes and edges."

  tags = {
    service = "AWS/VPC"
    type    = "Dashboard"
  }

  input "source_ip" {
    title = "Select a source IP address:"
    sql   = <<-EOQ
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
      -- Get source IP's direct connections
      with source_connections as (
        select
          src_addr,
          dst_addr,
          interface_id,
          ecs_task_id,
          ecs_service_name,
          ecs_cluster_name,
          count(*) as flow_count,
          sum(bytes) as total_bytes
        from
          aws_vpc_flow_log
        where
          src_addr = $1
        group by
          src_addr, dst_addr, interface_id, ecs_task_id, ecs_service_name, ecs_cluster_name
        having
          sum(bytes) >= cast($2 as bigint)
      ),
      
      -- Calculate traffic metrics for all nodes
      node_traffic as (
        -- Source IP node
        select
          $1 as node_id,
          sum(flow_count) as flow_count,
          sum(total_bytes) as total_bytes,
          sum(total_bytes) as total_bytes_out,
          0 as total_bytes_in
        from
          source_connections
        
        union all
        
        -- Destination IP nodes
        select
          dst_addr as node_id,
          sum(flow_count) as flow_count,
          sum(total_bytes) as total_bytes,
          0 as total_bytes_out,
          sum(total_bytes) as total_bytes_in
        from
          source_connections
        group by
          dst_addr
      ),
      
      -- Get potential return traffic for bidirectional measurement
      return_traffic as (
        select
          dst_addr as src_addr,
          $1 as dst_addr,
          count(*) as flow_count,
          sum(bytes) as total_bytes
        from
          aws_vpc_flow_log
        where
          dst_addr = $1
          and src_addr in (select dst_addr from source_connections)
        group by
          dst_addr, src_addr
      ),
      
      -- Combine outgoing and return traffic
      bidirectional_traffic as (
        select
          sc.src_addr as node1,
          sc.dst_addr as node2,
          sc.flow_count + coalesce(rt.flow_count, 0) as flow_count,
          sc.total_bytes + coalesce(rt.total_bytes, 0) as total_bytes,
          sc.interface_id,
          sc.ecs_task_id,
          sc.ecs_service_name,
          sc.ecs_cluster_name
        from
          source_connections sc
        left join
          return_traffic rt on sc.dst_addr = rt.src_addr
      ),
      
      -- Create IP nodes with traffic metrics
      ip_nodes as (
        -- Source IP
        select
          $1 as id,
          $1 || ' (' || 
            case 
              when sum(total_bytes) > 1048576 then round(cast(sum(total_bytes) as numeric) / 1048576, 2) || ' MB' 
              when sum(total_bytes) > 1024 then round(cast(sum(total_bytes) as numeric) / 1024, 2) || ' KB'
              else sum(total_bytes) || ' B'
            end || 
            ', ' || sum(flow_count) || ' flows)' as title,
          'source_ip' as category
        from
          node_traffic
        where
          node_id = $1
        
        union all
        
        -- Destination IPs
        select
          node_id as id,
          node_id || ' (' || 
            case 
              when total_bytes > 1048576 then round(cast(total_bytes as numeric) / 1048576, 2) || ' MB' 
              when total_bytes > 1024 then round(cast(total_bytes as numeric) / 1024, 2) || ' KB'
              else total_bytes || ' B'
            end || 
            ', ' || flow_count || ' flows)' as title,
          'destination_ip' as category
        from
          node_traffic
        where
          node_id != $1
      ),
      
      -- Get resource traffic
      resource_traffic as (
        select
          interface_id,
          sum(total_bytes) as eni_bytes
        from
          bidirectional_traffic
        where
          interface_id is not null
        group by
          interface_id
        
        union all
        
        select
          ecs_task_id as interface_id,
          sum(total_bytes) as eni_bytes
        from
          bidirectional_traffic
        where
          ecs_task_id is not null
        group by
          ecs_task_id
        
        union all
        
        select
          ecs_service_name as interface_id,
          sum(total_bytes) as eni_bytes
        from
          bidirectional_traffic
        where
          ecs_service_name is not null
        group by
          ecs_service_name
        
        union all
        
        select
          ecs_cluster_name as interface_id,
          sum(total_bytes) as eni_bytes
        from
          bidirectional_traffic
        where
          ecs_cluster_name is not null
        group by
          ecs_cluster_name
      ),
      
      -- Create ENI nodes
      eni_nodes as (
        select
          bt.interface_id as id,
          bt.interface_id || ' (' || 
            case 
              when rt.eni_bytes > 1048576 then round(cast(rt.eni_bytes as numeric) / 1048576, 2) || ' MB' 
              when rt.eni_bytes > 1024 then round(cast(rt.eni_bytes as numeric) / 1024, 2) || ' KB'
              else rt.eni_bytes || ' B'
            end || ')' as title,
          'eni' as category
        from
          bidirectional_traffic bt
        join
          resource_traffic rt on bt.interface_id = rt.interface_id
        where
          bt.interface_id is not null
        group by
          bt.interface_id, rt.eni_bytes
      ),
      
      -- Create ECS task nodes
      ecs_task_nodes as (
        select
          bt.ecs_task_id as id,
          bt.ecs_task_id || ' (' || 
            case 
              when rt.eni_bytes > 1048576 then round(cast(rt.eni_bytes as numeric) / 1048576, 2) || ' MB' 
              when rt.eni_bytes > 1024 then round(cast(rt.eni_bytes as numeric) / 1024, 2) || ' KB'
              else rt.eni_bytes || ' B'
            end || ')' as title,
          'ecs_task' as category
        from
          bidirectional_traffic bt
        join
          resource_traffic rt on bt.ecs_task_id = rt.interface_id
        where
          bt.ecs_task_id is not null
        group by
          bt.ecs_task_id, rt.eni_bytes
      ),
      
      -- Create ECS service nodes
      ecs_service_nodes as (
        select
          bt.ecs_service_name as id,
          bt.ecs_service_name || ' (' || 
            case 
              when rt.eni_bytes > 1048576 then round(cast(rt.eni_bytes as numeric) / 1048576, 2) || ' MB' 
              when rt.eni_bytes > 1024 then round(cast(rt.eni_bytes as numeric) / 1024, 2) || ' KB'
              else rt.eni_bytes || ' B'
            end || ')' as title,
          'ecs_service' as category
        from
          bidirectional_traffic bt
        join
          resource_traffic rt on bt.ecs_service_name = rt.interface_id
        where
          bt.ecs_service_name is not null
        group by
          bt.ecs_service_name, rt.eni_bytes
      ),
      
      -- Create ECS cluster nodes
      ecs_cluster_nodes as (
        select
          bt.ecs_cluster_name as id,
          bt.ecs_cluster_name || ' (' || 
            case 
              when rt.eni_bytes > 1048576 then round(cast(rt.eni_bytes as numeric) / 1048576, 2) || ' MB' 
              when rt.eni_bytes > 1024 then round(cast(rt.eni_bytes as numeric) / 1024, 2) || ' KB'
              else rt.eni_bytes || ' B'
            end || ')' as title,
          'ecs_cluster' as category
        from
          bidirectional_traffic bt
        join
          resource_traffic rt on bt.ecs_cluster_name = rt.interface_id
        where
          bt.ecs_cluster_name is not null
        group by
          bt.ecs_cluster_name, rt.eni_bytes
      ),
      
      -- Combine all nodes
      all_nodes as (
        select * from ip_nodes
        union all
        select * from eni_nodes
        union all
        select * from ecs_task_nodes
        union all
        select * from ecs_service_nodes
        union all
        select * from ecs_cluster_nodes
      ),
      
      -- Create IP-to-IP edges
      ip_edges as (
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
          bidirectional_traffic
      ),
      
      -- Create IP-to-ENI edges
      ip_eni_edges as (
        select
          node2 as from_id,
          interface_id as to_id,
          'via' as title
        from
          bidirectional_traffic
        where
          interface_id is not null
      ),
      
      -- Create ENI-to-ECS task edges
      eni_task_edges as (
        select
          interface_id as from_id,
          ecs_task_id as to_id,
          'attached to' as title
        from
          bidirectional_traffic
        where
          interface_id is not null
          and ecs_task_id is not null
      ),
      
      -- Create ECS task-to-service edges
      task_service_edges as (
        select
          ecs_task_id as from_id,
          ecs_service_name as to_id,
          'part of' as title
        from
          bidirectional_traffic
        where
          ecs_task_id is not null
          and ecs_service_name is not null
      ),
      
      -- Create ECS service-to-cluster edges
      service_cluster_edges as (
        select
          ecs_service_name as from_id,
          ecs_cluster_name as to_id,
          'in' as title
        from
          bidirectional_traffic
        where
          ecs_service_name is not null
          and ecs_cluster_name is not null
      ),
      
      -- Combine all edges
      all_edges as (
        select distinct * from ip_edges
        union all
        select distinct * from ip_eni_edges
        union all
        select distinct * from eni_task_edges
        union all
        select distinct * from task_service_edges
        union all
        select distinct * from service_cluster_edges
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
        all_edges.from_id,
        all_edges.to_id
      from
        all_edges
      where
        exists (select 1 from all_nodes where all_nodes.id = all_edges.from_id)
        and exists (select 1 from all_nodes where all_nodes.id = all_edges.to_id);
    EOQ
    args = [self.input.source_ip.value, self.input.min_traffic.value]
  }

  table {
    title = "Destination Details from Source IP"
    sql   = <<-EOQ
      select
        dst_addr as "Destination IP",
        action as "Action",
        case
          when protocol = 6 then 'TCP'
          when protocol = 17 then 'UDP'
          when protocol = 1 then 'ICMP'
          else protocol::text
        end as "Protocol",
        dst_port as "Port",
        flow_direction as "Direction",
        interface_id as "ENI",
        ecs_task_id as "ECS Task",
        ecs_service_name as "ECS Service",
        ecs_cluster_name as "ECS Cluster",
        count(*) as "Flow Count",
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
        dst_addr, action, protocol, dst_port, flow_direction, 
        interface_id, ecs_task_id, ecs_service_name, ecs_cluster_name
      having
        sum(bytes) >= cast($2 as bigint)
      order by
        sum(bytes) desc
      limit 50;
    EOQ
    args = [self.input.source_ip.value, self.input.min_traffic.value]
    width = 12
  }

  table {
    title = "Return Traffic to Source IP"
    sql   = <<-EOQ
      select
        src_addr as "Source IP",
        action as "Action",
        case
          when protocol = 6 then 'TCP'
          when protocol = 17 then 'UDP'
          when protocol = 1 then 'ICMP'
          else protocol::text
        end as "Protocol",
        src_port as "Port",
        flow_direction as "Direction",
        interface_id as "ENI",
        ecs_task_id as "ECS Task",
        count(*) as "Flow Count",
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
        dst_addr = $1
      group by
        src_addr, action, protocol, src_port, flow_direction, 
        interface_id, ecs_task_id
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