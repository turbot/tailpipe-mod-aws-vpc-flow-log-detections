dashboard "vpc_flow_log_traffic_overview" {
  title         = "VPC Flow Log Traffic Overview Dashboard"
  documentation = file("./dashboards/docs/vpc_flow_log_traffic_overview.md")

  tags = {
    type    = "Dashboard"
    service = "AWS/VPCFlowLogs"
  }

  container {
    # Summary cards
    card {
      query = query.vpc_flow_log_total_logs
      width = 2
    }

    card {
      query = query.vpc_flow_log_total_traffic_volume
      width = 2
    }

    card {
      query = query.vpc_flow_log_total_packets
      width = 2
    }
  }

  container {
    chart {
      title = "Accepted vs. Rejected Traffic Volume Over Time"
      query = query.vpc_flow_log_accepted_vs_rejected_over_time
      type  = "line"
      width = 6

      series "accepted" {
        color = "green"
      }

      series "rejected" {
        color = "red"
      }

      axes {
        x {
          title {
            value = "Time (Hourly)"
          }
          labels {
            display = "auto"
          }
        }
        y {
          title {
            value = "Bytes"
          }
          labels {
            display = "auto"
          }
        }
      }
    }

    chart {
      title = "Ingress vs. Egress Traffic Volume Over Time"
      query = query.vpc_flow_log_ingress_vs_egress_over_time
      type  = "line"
      width = 6

      series "ingress" {
        color = "blue"
      }

      series "egress" {
        color = "orange"
      }

      axes {
        x {
          title {
            value = "Time (Hourly)"
          }
          labels {
            display = "auto"
          }
        }
        y {
          title {
            value = "Bytes"
          }
          labels {
            display = "auto"
          }
        }
      }
    }

    chart {
      title = "Egress Traffic Path Analysis"
      query = query.vpc_flow_log_egress_path_analysis
      type  = "column"
      width = 6

      series "Total Bytes" {
        color = "purple"
      }

      axes {
        x {
          title {
            value = "Path Type"
          }
          labels {
            display = "auto"
          }
        }
        y {
          title {
            value = "Bytes"
          }
          labels {
            display = "auto"
          }
        }
      }
    }

    chart {
      title = "Traffic Distribution by Region"
      query = query.vpc_flow_log_traffic_by_region
      type  = "column"
      width = 6

      axes {
        x {
          title {
            value = "Region"
          }
          labels {
            display = "auto"
          }
        }
        y {
          title {
            value = "Bytes"
          }
          labels {
            display = "auto"
          }
        }
      }
    }

    chart {
      title = "HTTP Requests (Port 80 Traffic)"
      query = query.vpc_flow_log_http_requests
      type  = "line"
      width = 6

      series "request_count" {
        color = "orange"
      }

      axes {
        x {
          title {
            value = "Time (Hourly)"
          }
          labels {
            display = "auto"
          }
        }
        y {
          title {
            value = "Count"
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

      series "request_count" {
        color = "green"
      }

      axes {
        x {
          title {
            value = "Time (Hourly)"
          }
          labels {
            display = "auto"
          }
        }
        y {
          title {
            value = "Count"
          }
          labels {
            display = "auto"
          }
        }
      }
    }

    chart {
      title = "Traffic Distribution by Protocol"
      query = query.vpc_flow_log_traffic_by_protocol
      type  = "pie"
      width = 6
    }

    chart {
      title = "Top 10 IP Addresses by Total Traffic"
      query = query.vpc_flow_log_top_ips_by_traffic
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 IP Addresses by Rejected Traffic"
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

    chart {
      title = "Top 10 IP Addresses Where Flow Records Were Skipped"
      query = query.vpc_flow_log_skipped_records
      type  = "table"
      width = 6
    }
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

query "vpc_flow_log_total_traffic_volume" {
  title       = "Total Traffic in Bytes"
  description = "Sum of all bytes transferred in VPC Flow Logs."

  sql = <<-EOQ
    select
      sum(bytes) as "Total Traffic in Bytes"
    from
      aws_vpc_flow_log;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_total_packets" {
  title       = "Total Traffic in Packets"
  description = "Sum of all packets transferred in VPC Flow Logs."

  sql = <<-EOQ
    select
      sum(packets) as "Total Traffic in Packets"
    from
      aws_vpc_flow_log;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_accepted_vs_rejected_over_time" {
  title       = "Accepted vs. Rejected Traffic Over Time"
  description = "Comparison of accepted and rejected traffic volume over the past 7 days."

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

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_top_ips_by_traffic" {
  title       = "Top 10 IP Addresses by Traffic"
  description = "List the top 10 source IP addresses generating the most traffic."

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
    limit 10
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
    limit 10
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_http_requests" {
  title       = "HTTP Traffic Over Time"
  description = "Count of HTTP requests (port 80) over the past 7 days."

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

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_https_requests" {
  title       = "HTTPS Traffic Over Time"
  description = "Count of HTTPS requests (port 443) over the past 7 days."

  sql = <<-EOQ
    with time_series as (
      select
        date_trunc('hour', start_time) as hour,
        count(*) as request_count
      from
        aws_vpc_flow_log
      where
        start_time >= (current_date - interval '7' day)
        and dst_port = 443
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

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_traffic_by_protocol" {
  title       = "Traffic by Protocol"
  description = "Distribution of traffic volume across different protocols."

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

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_traffic_by_region" {
  title       = "Traffic by Region"
  description = "Distribution of traffic volume across different AWS regions."

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

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_ingress_vs_egress_over_time" {
  title       = "Ingress vs. Egress Traffic Over Time"
  description = "Comparison of ingress and egress traffic volume over the past 7 days."

  sql = <<-EOQ
    with time_series as (
      select
        date_trunc('hour', start_time) as hour,
        sum(bytes) filter (where flow_direction = 'ingress') as ingress,
        sum(bytes) filter (where flow_direction = 'egress') as egress
      from
        aws_vpc_flow_log
      where
        start_time >= (current_date - interval '7' day)
        and flow_direction is not null
      group by
        hour
      order by
        hour
    )
    select
      hour,
      ingress,
      egress
    from
      time_series
    order by
      hour
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "vpc_flow_log_egress_path_analysis" {
  title       = "Egress Traffic Path Analysis"
  description = "Distribution of egress traffic across different path types."

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
      sum(bytes) as "Total Bytes"
    from
      aws_vpc_flow_log
    where
      flow_direction = 'egress'
      and traffic_path is not null
    group by
      traffic_path
    order by
      "Total Bytes" desc
  EOQ

  tags = {
    folder = "VPC"
  }
} 