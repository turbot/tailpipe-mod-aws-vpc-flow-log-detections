dashboard "vpc_flow_log_traffic_overview" {
  title = "VPC Flow Log Traffic Overview"

  chart {
    title = "Total Traffic Volume Over Time"
    query = query.vpc_flow_log_total_traffic_over_time
    width = 6
    type  = "line"
  }

  chart {
    title = "Accepted vs. Rejected Traffic Volume Over Time"
    query = query.vpc_flow_log_accepted_vs_rejected_over_time
    width = 6
    type  = "line"

    series "accepted" {
      color = "green"
    }

    series "rejected" {
      color = "red"
    }
  }

  table {
    title = "Top 10 IP Addresses by Total Traffic"
    query = query.vpc_flow_log_top_ips_by_traffic
    width = 6
  }

  table {
    title = "Top 10 IP Addresses by Rejected Traffic"
    query = query.vpc_flow_log_top_ips_by_rejects
    width = 6
  }

  table {
    title = "Top 15 Packet Transfers Across Hosts"
    query = query.vpc_flow_log_top_packet_transfers
    width = 6
  }

  table {
    title = "Top Byte Transfers by Subnet"
    query = query.vpc_flow_log_top_byte_transfers_by_subnet
    width = 6
  }

  table {
    title = "IP Addresses Where Flow Records Were Skipped"
    query = query.vpc_flow_log_skipped_records
    width = 6
  }

  chart {
    title = "Egress Data Points (Outbound Traffic by Destination)"
    query = query.vpc_flow_log_egress_data_points
    width = 6
    type  = "column"
  }

  chart {
    title = "HTTP Requests (Port 80 Traffic)"
    query = query.vpc_flow_log_http_requests
    width = 6
    type  = "line"
  }

  chart {
    title = "Traffic Distribution by Protocol"
    query = query.vpc_flow_log_traffic_by_protocol
    width = 6
    type  = "pie"
  }

  chart {
    title = "Traffic Distribution by Region"
    query = query.vpc_flow_log_traffic_by_region
    width = 6
    type  = "column"
  }
}

query "vpc_flow_log_total_traffic_over_time" {
  sql = <<-EOQ
    with time_series as (
      select
        date_trunc('hour', start_time) as hour,
        sum(bytes) as total_bytes
      from
        aws_vpc_flow_log
      where
        start_time >= (current_date - interval '7' day)
      group by
        hour
      order by
        hour
    )
    select
      hour,
      total_bytes
    from
      time_series
    order by
      hour
  EOQ
}

query "vpc_flow_log_accepted_vs_rejected_over_time" {
  sql = <<-EOQ
    with time_series as (
      select
        date_trunc('hour', start_time) as hour,
        sum(bytes) filter (where action = 'ACCEPT') as accepted,
        sum(bytes) filter (where action = 'REJECT') as rejected
      from
        aws_vpc_flow_log
      where
        start_time >= (current_date - interval '7' day)
      group by
        hour
      order by
        hour
    )
    select
      hour,
      accepted,
      rejected
    from
      time_series
    order by
      hour
  EOQ
}

query "vpc_flow_log_top_ips_by_traffic" {
  sql = <<-EOQ
    select
      src_addr as "Source IP",
      count(*) as "Connection Count",
      sum(bytes) as "Total Bytes",
      sum(packets) as "Total Packets",
      max(start_time) as "Last Seen"
    from
      aws_vpc_flow_log
    where
      src_addr is not null
    group by
      src_addr
    order by
      "Total Bytes" desc
    limit 10
  EOQ
}

query "vpc_flow_log_top_ips_by_rejects" {
  sql = <<-EOQ
    select
      src_addr as "Source IP",
      count(*) as "Rejected Count",
      sum(bytes) as "Total Bytes Rejected",
      sum(packets) as "Total Packets Rejected",
      max(start_time) as "Last Rejected"
    from
      aws_vpc_flow_log
    where
      src_addr is not null
      and action = 'REJECT'
    group by
      src_addr
    order by
      "Rejected Count" desc
    limit 10
  EOQ
}

query "vpc_flow_log_top_packet_transfers" {
  sql = <<-EOQ
    select
      src_addr as "Source IP",
      dst_addr as "Destination IP",
      sum(packets) as "Total Packets",
      sum(bytes) as "Total Bytes",
      count(*) as "Connection Count",
      max(start_time) as "Last Seen"
    from
      aws_vpc_flow_log
    where
      src_addr is not null
      and dst_addr is not null
    group by
      src_addr, dst_addr
    order by
      "Total Packets" desc
    limit 15
  EOQ
}

query "vpc_flow_log_top_byte_transfers_by_subnet" {
  sql = <<-EOQ
    with subnet_data as (
      -- Extract /24 subnet using split_part
      select
        src_addr,
        dst_addr,
        -- Extract first 3 octets and append .0/24
        split_part(src_addr, '.', 1) || '.' || split_part(src_addr, '.', 2) || '.' || split_part(src_addr, '.', 3) || '.0/24' as src_subnet,
        split_part(dst_addr, '.', 1) || '.' || split_part(dst_addr, '.', 2) || '.' || split_part(dst_addr, '.', 3) || '.0/24' as dst_subnet,
        sum(bytes) as total_bytes,
        sum(packets) as total_packets,
        count(*) as connection_count,
        max(start_time) as last_seen
      from
        aws_vpc_flow_log
      where
        src_addr is not null
        and dst_addr is not null
      group by
        src_addr, dst_addr
    ),
    
    -- Group by subnet pairs
    subnet_transfers as (
      select
        src_subnet as "Source Subnet",
        dst_subnet as "Destination Subnet",
        sum(total_bytes) as "Total Bytes",
        sum(total_packets) as "Total Packets",
        sum(connection_count) as "Connection Count",
        max(last_seen) as "Last Seen"
      from
        subnet_data
      group by
        src_subnet, dst_subnet
      order by
        "Total Bytes" desc
      limit 15
    )
    
    select * from subnet_transfers
  EOQ
}

query "vpc_flow_log_skipped_records" {
  sql = <<-EOQ
    select
      src_addr as "Source IP",
      dst_addr as "Destination IP",
      log_status as "Log Status",
      count(*) as "Skip Count",
      max(start_time) as "Last Observed"
    from
      aws_vpc_flow_log
    where
      log_status = 'SKIPDATA'
    group by
      src_addr, dst_addr, log_status
    order by
      "Skip Count" desc
    limit 50
  EOQ
}

query "vpc_flow_log_egress_data_points" {
  sql = <<-EOQ
    select
      case
        when flow_direction = 'egress' then 'Egress'
        when traffic_path in (2, 5, 7, 9) then 'Egress Path'
        else 'Other Outbound'
      end as direction_type,
      sum(bytes) as total_bytes
    from
      aws_vpc_flow_log
    where
      (flow_direction = 'egress' or traffic_path in (2, 5, 7, 9))
    group by
      direction_type
    order by
      total_bytes desc
  EOQ
}

query "vpc_flow_log_http_requests" {
  sql = <<-EOQ
    with time_series as (
      select
        date_trunc('hour', start_time) as hour,
        count(*) as request_count
      from
        aws_vpc_flow_log
      where
        start_time >= (current_date - interval '7' day)
        and dst_port = 80
        and action = 'ACCEPT'
      group by
        hour
      order by
        hour
    )
    
    select
      hour,
      request_count
    from
      time_series
    order by
      hour
  EOQ
}

query "vpc_flow_log_traffic_by_protocol" {
  sql = <<-EOQ
    select
      case
        when protocol = 1 then 'ICMP'
        when protocol = 6 then 'TCP'
        when protocol = 17 then 'UDP'
        else 'Other'
      end as protocol,
      sum(bytes) as total_bytes
    from
      aws_vpc_flow_log
    where
      protocol is not null
    group by
      protocol
    order by
      total_bytes desc
  EOQ
}

query "vpc_flow_log_traffic_by_region" {
  sql = <<-EOQ
    select
      region,
      sum(bytes) as total_bytes
    from
      aws_vpc_flow_log
    where
      region is not null
    group by
      region
    order by
      total_bytes desc
    limit 10
  EOQ
} 