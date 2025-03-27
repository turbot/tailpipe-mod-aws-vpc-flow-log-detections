dashboard "vpc_flow_log_comprehensive_network_analysis" {
  title         = "VPC Flow Log Comprehensive Network Analysis"
  documentation = "Visualizes network traffic from a specific source IP address to all associated AWS resources, including ENI connections."

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
        src_addr;
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
          -- EC2 and VPC resources
          instance_id,
          interface_id,
          subnet_id,
          vpc_id,
          -- ECS resources
          ecs_task_id,
          ecs_cluster_name,
          ecs_service_name,
          ecs_container_id,
          -- Other metadata
          action,
          protocol,
          dst_port,
          flow_direction,
          -- Traffic metrics
          sum(bytes) as total_bytes,
          count(*) as connection_count
        from 
          aws_vpc_flow_log
        where
          src_addr = $1
          and dst_addr is not null
        group by 
          src_addr, dst_addr, instance_id, interface_id, subnet_id, vpc_id,
          ecs_task_id, ecs_cluster_name, ecs_service_name, ecs_container_id,
          action, protocol, dst_port, flow_direction
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
      -- EC2 and Network Resource nodes
      network_nodes as (
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
        
        -- ENIs (Elastic Network Interfaces)
        select distinct
          interface_id as id,
          interface_id as title,
          'eni' as category
        from
          traffic_data
        where
          interface_id is not null
          
        union all
        
        -- Subnets
        select distinct
          subnet_id as id,
          subnet_id as title,
          'subnet' as category
        from
          traffic_data
        where
          subnet_id is not null
          
        union all
        
        -- VPCs
        select distinct
          vpc_id as id,
          vpc_id as title,
          'vpc' as category
        from
          traffic_data
        where
          vpc_id is not null
      ),
      -- ECS Resource nodes
      ecs_nodes as (
        -- ECS Tasks
        select distinct
          ecs_task_id as id,
          ecs_task_id as title,
          'ecs_task' as category
        from
          traffic_data
        where
          ecs_task_id is not null
          
        union all
        
        -- ECS Clusters
        select distinct
          ecs_cluster_name as id,
          ecs_cluster_name as title,
          'ecs_cluster' as category
        from
          traffic_data
        where
          ecs_cluster_name is not null
          
        union all
        
        -- ECS Services
        select distinct
          ecs_service_name as id,
          ecs_service_name as title,
          'ecs_service' as category
        from
          traffic_data
        where
          ecs_service_name is not null
      ),
      -- Protocol nodes
      protocol_nodes as (
        select distinct
          case
            when protocol = 6 then 'TCP'
            when protocol = 17 then 'UDP'
            when protocol = 1 then 'ICMP'
            else 'Protocol_' || protocol::text
          end as id,
          case
            when protocol = 6 then 'TCP'
            when protocol = 17 then 'UDP'
            when protocol = 1 then 'ICMP'
            else 'Protocol_' || protocol::text
          end as title,
          'protocol' as category
        from
          traffic_data
        where
          protocol is not null
      ),
      -- All nodes combined
      all_nodes as (
        select * from ip_nodes
        union all
        select * from network_nodes
        union all
        select * from ecs_nodes
        union all
        select * from protocol_nodes
      ),
      -- Edge definitions
      traffic_edges as (
        -- Source to destination IP edges
        select
          src_addr as from_id,
          dst_addr as to_id,
          count(*) || ' flows, ' || 
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
        
        -- NEW: Destination IP to ENI edges - explicit connection between destination IPs and ENIs
        select
          dst_addr as from_id,
          interface_id as to_id,
          'received by' as title
        from
          traffic_data
        where
          interface_id is not null
        group by
          dst_addr, interface_id
          
        union all
        
        -- Destination to EC2 instance edges
        select
          dst_addr as from_id,
          instance_id as to_id,
          'runs on' as title
        from
          traffic_data
        where
          instance_id is not null
        group by
          dst_addr, instance_id
          
        union all
        
        -- NEW: ENI to ECS task edges - connect ENIs to ECS tasks
        select
          interface_id as from_id,
          ecs_task_id as to_id,
          'attached to' as title
        from
          traffic_data
        where
          interface_id is not null
          and ecs_task_id is not null
        group by
          interface_id, ecs_task_id
          
        union all
        
        -- EC2 instance to ENI edges
        select
          instance_id as from_id,
          interface_id as to_id,
          'uses' as title
        from
          traffic_data
        where
          instance_id is not null
          and interface_id is not null
        group by
          instance_id, interface_id
          
        union all
        
        -- ENI to subnet edges
        select
          interface_id as from_id,
          subnet_id as to_id,
          'in' as title
        from
          traffic_data
        where
          interface_id is not null
          and subnet_id is not null
        group by
          interface_id, subnet_id
          
        union all
        
        -- Subnet to VPC edges
        select
          subnet_id as from_id,
          vpc_id as to_id,
          'part of' as title
        from
          traffic_data
        where
          subnet_id is not null
          and vpc_id is not null
        group by
          subnet_id, vpc_id
          
        union all
        
        -- Destination to ECS task edges
        select
          dst_addr as from_id,
          ecs_task_id as to_id,
          'task' as title
        from
          traffic_data
        where
          ecs_task_id is not null
        group by
          dst_addr, ecs_task_id
          
        union all
        
        -- ECS task to service edges
        select
          ecs_task_id as from_id,
          ecs_service_name as to_id,
          'service' as title
        from
          traffic_data
        where
          ecs_task_id is not null
          and ecs_service_name is not null
        group by
          ecs_task_id, ecs_service_name
          
        union all
        
        -- ECS service to cluster edges
        select
          ecs_service_name as from_id,
          ecs_cluster_name as to_id,
          'in cluster' as title
        from
          traffic_data
        where
          ecs_service_name is not null
          and ecs_cluster_name is not null
        group by
          ecs_service_name, ecs_cluster_name
          
        union all
        
        -- Destination to protocol edges
        select
          dst_addr as from_id,
          case
            when protocol = 6 then 'TCP'
            when protocol = 17 then 'UDP'
            when protocol = 1 then 'ICMP'
            else 'Protocol_' || protocol::text
          end as to_id,
          'uses' as title
        from
          traffic_data
        where
          protocol is not null
        group by
          dst_addr, protocol
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
        traffic_edges
      where
        exists (select 1 from all_nodes where all_nodes.id = traffic_edges.from_id)
        and exists (select 1 from all_nodes where all_nodes.id = traffic_edges.to_id);
    EOQ
    args = [self.input.source_ip.value, self.input.min_traffic.value]
  }

  table {
    title = "Comprehensive Resource Details for Source IP"
    sql   = <<-EOQ
      select
        dst_addr as "Destination IP",
        action as "Action",
        protocol as "Protocol",
        dst_port as "Port",
        flow_direction as "Direction",
        instance_id as "EC2 Instance",
        interface_id as "ENI",
        subnet_id as "Subnet",
        vpc_id as "VPC",
        ecs_task_id as "ECS Task",
        ecs_cluster_name as "ECS Cluster",
        ecs_service_name as "ECS Service",
        count(*) as "Flow Count",
        sum(bytes) as "Bytes",
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
        instance_id, interface_id, subnet_id, vpc_id,
        ecs_task_id, ecs_cluster_name, ecs_service_name
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