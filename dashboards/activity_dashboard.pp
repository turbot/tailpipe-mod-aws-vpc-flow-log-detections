dashboard "activity_dashboard" {
  title         = "VPC Flow Log Activity Dashboard"
  documentation = file("./dashboards/docs/activity_dashboard.md")

  tags = {
    type    = "Dashboard"
    service = "AWS/VPC"
  }

  container {
    # Summary cards
    card {
      query = query.vpc_flow_log_total_logs
      width = 2
    }

    card {
      query = query.vpc_flow_log_total_volume_in_bytes
      width = 2
    }

    card {
      query = query.vpc_flow_log_total_packets
      width = 2
    }
  }

  container {

    chart {
      title = "Connections by Region"
      query = query.vpc_flow_log_traffic_by_region
      type  = "column"
      width = 6
    }

    chart {
      title = "Connections by Protocol"
      query = query.vpc_flow_log_traffic_by_protocol
      type  = "donut"
      width = 6
    }

    chart {
      title = "Accepted vs. Rejected Connections"
      query = query.vpc_flow_log_accepted_vs_rejected
      type  = "line"
      width = 6

      series "accepted" {
        color = "green"
      }

      series "rejected" {
        color = "red"
      }
    }

    /*
    chart {
      title = "Ingress vs. Egress Connections"
      query = query.vpc_flow_log_ingress_vs_egress
      type  = "line"
      width = 6

      series "ingress" {
        color = "blue"
      }

      series "egress" {
        color = "orange"
      }
    }

    chart {
      title = "Egress Traffic Path Analysis"
      query = query.vpc_flow_log_egress_path_analysis
      type  = "column"
      width = 6

      series "Connections" {
        color = "purple"
      }
    }

    chart {
      title = "HTTP Requests (Port 80 Traffic)"
      query = query.vpc_flow_log_http_requests
      type  = "line"
      width = 6

      series "Connections" {
        color = "orange"
      }

      axes {
        x {
          title {
            value = "Time (Daily)"
          }
          labels {
            display = "auto"
          }
        }
        y {
          title {
            value = "Connections"
          }
          labels {
            display = "auto"
          }
        }
      }
    }

    chart {
      title = "HTTPS Requests (Port 443 Traffic)"
      query = query.vpc_flow_log_https_requests
      type  = "line"
      width = 6

      series "Connections" {
        color = "green"
      }

      axes {
        x {
          title {
            value = "Time (Daily)"
          }
          labels {
            display = "auto"
          }
        }
        y {
          title {
            value = "Connections"
          }
          labels {
            display = "auto"
          }
        }
      }
    }
    */

    chart {
      title = "Top 10 Source IPs"
      query = query.vpc_flow_log_top_ips_by_traffic
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Rejected Source IPs"
      query = query.vpc_flow_log_top_ips_by_rejects
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Packet Transfers Across Hosts"
      query = query.vpc_flow_log_top_packet_transfers
      type  = "table"
      width = 6
    }

    /*
    chart {
      title = "Top 10 IP Addresses Where Flow Records Were Skipped"
      query = query.vpc_flow_log_skipped_records
      type  = "table"
      width = 6
    }
    */

  }
}

# Query definitions

query "vpc_flow_log_total_logs" {
  title       = "Log Count"
  description = "Count the total VPC Flow Log entries."

  sql = <<-EOQ
    select
      count(*) as "Total Logs"
    from
      aws_vpc_flow_log;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_total_volume_in_bytes" {
  title       = "Total Bytes"
  description = "Sum of all bytes transferred in VPC Flow Logs."

  sql = <<-EOQ
    select
      sum(bytes) as "Total Bytes"
    from
      aws_vpc_flow_log;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_total_packets" {
  title       = "Total Packets"
  description = "Sum of all packets transferred in VPC Flow Logs."

  sql = <<-EOQ
    select
      sum(packets) as "Total Packets"
    from
      aws_vpc_flow_log;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_accepted_vs_rejected" {
  title       = "Accepted vs. Rejected Connections"
  description = "Comparison of accepted and rejected connection counts."

  sql = <<-EOQ
    with time_series as (
      select
        date_trunc('day', start_time) as day,
        count(*) filter (where action = 'ACCEPT') as accepted,
        count(*) filter (where action = 'REJECT') as rejected
      from
        aws_vpc_flow_log
      group by
        day
      order by
        day
    )
    select
      day,
      accepted,
      rejected
    from
      time_series
    order by
      day;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_top_ips_by_traffic" {
  title       = "Top 10 IP Addresses"
  description = "List the top 10 source IP addresses generating the most traffic."

  sql = <<-EOQ
    select
      src_addr as "Source IP",
      count(*) as "Connections",
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
      "Connections" desc
    limit 10;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_top_ips_by_rejects" {
  title       = "Top 10 IP Addresses by Rejected Traffic"
  description = "List the top 10 source IP addresses with the most rejected connections."

  sql = <<-EOQ
    select
      src_addr as "Source IP",
      count(*) as "Connections",
      sum(bytes) as "Total Bytes",
      sum(packets) as "Total Packets",
      max(start_time) as "Last Rejected"
    from
      aws_vpc_flow_log
    where
      src_addr is not null
      and action = 'REJECT'
    group by
      src_addr
    order by
      "Connections" desc
    limit 10;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_top_packet_transfers" {
  title       = "Top 10 Packet Transfers"
  description = "List the top 10 source-destination pairs with the highest packet counts."

  sql = <<-EOQ
    select
      src_addr as "Source IP",
      dst_addr as "Destination IP",
      sum(packets) as "Total Packets",
      sum(bytes) as "Total Bytes",
      count(*) as "Connections",
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
    limit 10;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_skipped_records" {
  title       = "Top 10 IP Addresses Where Flow Records Were Skipped"
  description = "List IP addresses where flow records were skipped, indicating potential capacity issues."

  sql = <<-EOQ
    select
      src_addr as "Source IP",
      count(*) as "Skip Count",
      dst_addr as "Destination IP",
      log_status as "Log Status",
      max(start_time) as "Last Observed"
    from
      aws_vpc_flow_log
    where
      log_status = 'SKIPDATA'
    group by
      src_addr, dst_addr, log_status
    order by
      "Skip Count" desc
    limit 10;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_http_requests" {
  title       = "HTTP Traffic"
  description = "Count of HTTP requests (port 80)."

  sql = <<-EOQ
    with time_series as (
      select
        date_trunc('day', start_time) as day,
        count(*) as request_count
      from
        aws_vpc_flow_log
      where
        dst_port = 80
        and action = 'ACCEPT'
      group by
        day
      order by
        day
    )
    select
      day,
      request_count as "Connections"
    from
      time_series
    order by
      day;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_https_requests" {
  title       = "HTTPS Traffic"
  description = "Count of HTTPS requests (port 443)."

  sql = <<-EOQ
    with time_series as (
      select
        date_trunc('day', start_time) as day,
        count(*) as request_count
      from
        aws_vpc_flow_log
      where
        dst_port = 443
        and action = 'ACCEPT'
      group by
        day
      order by
        day
    )
    select
      day,
      request_count as "Connections"
    from
      time_series
    order by
      day;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_traffic_by_protocol" {
  title       = "Traffic by Protocol"
  description = "Distribution of connection counts across different protocols."

  sql = <<-EOQ
    select
      case
        when protocol = 1 then 'ICMP'
        when protocol = 6 then 'TCP'
        when protocol = 17 then 'UDP'
        else 'Other'
      end as protocol,
      count(*) as "Connections"
    from
      aws_vpc_flow_log
    where
      protocol is not null
    group by
      case
        when protocol = 1 then 'ICMP'
        when protocol = 6 then 'TCP'
        when protocol = 17 then 'UDP'
        else 'Other'
      end
    order by
      "Connections" desc;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_traffic_by_region" {
  title       = "Traffic by Region"
  description = "Distribution of connection counts across different AWS regions."

  sql = <<-EOQ
    select
      region,
      count(*) as "Connections"
    from
      aws_vpc_flow_log
    where
      region is not null
    group by
      region
    order by
      "Connections" desc;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_ingress_vs_egress" {
  title       = "Ingress vs. Egress Connections"
  description = "Comparison of ingress and egress connection counts."

  sql = <<-EOQ
    with time_series as (
      select
        date_trunc('day', start_time) as day,
        count(*) filter (where flow_direction = 'ingress') as ingress,
        count(*) filter (where flow_direction = 'egress') as egress
      from
        aws_vpc_flow_log
      where
        flow_direction is not null
      group by
        day
      order by
        day
    )
    select
      day,
      ingress,
      egress
    from
      time_series
    order by
      day;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_egress_path_analysis" {
  title       = "Egress Traffic Path Analysis"
  description = "Distribution of egress connections across different path types."

  sql = <<-EOQ
    select
      case traffic_path
        when 1 then 'Through Another Resource in Same VPC'
        when 2 then 'Through Internet Gateway or Gateway VPC Endpoint'
        when 3 then 'Through Virtual Private Gateway'
        when 4 then 'Through Intra-Region VPC Peering'
        when 5 then 'Through Inter-Region VPC Peering'
        when 6 then 'Through Local Gateway'
        when 7 then 'Through Gateway VPC Endpoint (Nitro)'
        when 8 then 'Through Internet Gateway (Nitro)'
        else 'Other/Unknown'
      end as "Path Type",
      count(*) as "Connections"
    from
      aws_vpc_flow_log
    where
      flow_direction = 'egress'
      and traffic_path is not null
    group by
      traffic_path
    order by
      "Connections" desc;
  EOQ

  tags = {
    folder = "VPC"
  }
}
