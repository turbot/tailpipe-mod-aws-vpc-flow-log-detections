category "ip_address" {
  title = "IP Address"
  icon  = "server"
}

dashboard "network_graph" {
  title         = "VPC Flow Log Network Graph"
  documentation = file("./dashboards/docs/network_graph.md")

  tags = {
    type    = "Dashboard"
    service = "AWS/VPC"
  }

  graph {
    type      = "graph"
    direction = "LR"

    category "high_conn_count" {
      color = "orange"
    }

    node {
      category = category.ip_address

      sql = <<-EOQ
        -- Get all unique IPs (both source and destination)
        with all_ips as (
          select
            distinct(src_addr) as ip
          from
            aws_vpc_flow_log
          where
            src_addr is not null

          union

          select
            distinct(dst_addr) as ip
          from
            aws_vpc_flow_log
          where
            dst_addr is not null
        )
          select
            ip as id,
            ip as title,
          from
            all_ips
          order by
            ip
          limit 5000;
        EOQ

        tags = {
          folder = "Hidden"
        }
      }

    edge {
      sql = <<-EOQ
        with ip_pairs as (
          -- Get connections where IP1 is source and IP2 is destination
          select
            src_addr as ip1,
            dst_addr as ip2,
            count(*) as connection_count
          from
            aws_vpc_flow_log
          where
            src_addr is not null
            and dst_addr is not null
          group by
            src_addr,
            dst_addr

          union all

          -- Get connections where IP1 is destination and IP2 is source
          select
            dst_addr as ip1,
            src_addr as ip2,
            count(*) as connection_count
          from
            aws_vpc_flow_log
          where
            src_addr is not null
            and dst_addr is not null
          group by
            dst_addr,
            src_addr
        )
        -- Aggregate to get total connections between each unique pair of IPs
        select
          case when ip1 < ip2 then ip1 else ip2 end as from_id,
          case when ip1 < ip2 then ip2 else ip1 end as to_id,
          case
            when sum(connection_count) > 50 then 'high_conn_count'
          end as category,
          sum(connection_count) as title
        from
          ip_pairs
        group by
          from_id,
          to_id
        having
          from_id != to_id -- Exclude self-connections
        order by
          from_id;
      EOQ

      tags = {
        folder = "Hidden"
      }
    }
  }
}
