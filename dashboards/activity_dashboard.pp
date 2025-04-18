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
      query = query.activity_dashboard_total_records
      width = 2
    }

    card {
      query = query.activity_dashboard_total_accepted_traffic
      width = 2
    }

    card {
      query = query.activity_dashboard_total_rejected_traffic
      width = 2
    }
  }

  container {

    chart {
      title = "Accepted vs. Rejected Traffic"
      query = query.activity_dashboard_accepted_rejected_traffic
      type  = "line"
      width = 6

      series "accepted" {
        color = "green"
      }

      series "rejected" {
        color = "red"
      }
    }

    chart {
      title = "Traffic by Log Status"
      query = query.activity_dashboard_traffic_by_log_status
      type  = "donut"
      width = 6
    }

    chart {
      title = "Traffic by Region"
      query = query.activity_dashboard_traffic_by_region
      type  = "bar"
      width = 6
    }

    chart {
      title = "Traffic by Protocol"
      query = query.activity_dashboard_traffic_by_protocol
      type  = "donut"
      width = 6
    }

    chart {
      title = "Top 10 ENIs by Traffic"
      query = query.activity_dashboard_top_enis_by_traffic
      type  = "table"
      width = 12
    }

    chart {
      title = "Top 10 Source IPs by Traffic"
      query = query.activity_dashboard_top_source_ips_by_traffic
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Destination IPs by Traffic"
      query = query.activity_dashboard_top_destination_ips_by_traffic
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Rejected Source IPs"
      query = query.activity_dashboard_top_source_ips_by_rejected_traffic
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Packet Transfers Across Hosts"
      query = query.activity_dashboard_top_source_destination_pairs_by_packets
      type  = "table"
      width = 6
    }
  }
}

# Query definitions

query "activity_dashboard_total_records" {
  title       = "Record Count"
  description = "Count the total VPC flow log records, excluding records that are skipped or have no data."

  sql = <<-EOQ
    select
      count(*) as "Total Records"
    from
      aws_vpc_flow_log;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "activity_dashboard_total_accepted_traffic" {
  title       = "Accepted Traffic Count"
  description = "Count the total VPC flow log records with accepted traffic."

  sql = <<-EOQ
    select
      count(*) as "Accepted Traffic"
    from
      aws_vpc_flow_log
    where
      action = 'ACCEPT';
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "activity_dashboard_total_rejected_traffic" {
  title       = "Rejected Traffic Count"
  description = "Count the total VPC flow log records with rejected traffic."

  sql = <<-EOQ
    select
      count(*) as "Rejected Traffic"
    from
      aws_vpc_flow_log
    where
      action = 'REJECT';
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "activity_dashboard_accepted_rejected_traffic" {
  title       = "Accepted vs. Rejected Traffic"
  description = "Comparison of accepted and rejected record counts."

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

query "activity_dashboard_traffic_by_log_status" {
  title       = "Traffic by Log Status"
  description = "Distribution of record counts by log status."

  sql = <<-EOQ
    select
      log_status,
      count(*) as "Records"
    from
      aws_vpc_flow_log
    where
      log_status is not null
    group by
      log_status
    order by
      "Records" desc,
      log_status;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "activity_dashboard_top_enis_by_traffic" {
  title       = "Top 10 ENIs by Traffic"
  description = "List the top 10 ENIs generating the most traffic."

  sql = <<-EOQ
    select
      interface_id as "ENI",
      vpc_id as "VPC",
      subnet_id as "Subnet",
      account_id as "Account",
      region as "Region",
      count(*) as "Records",
      coalesce(sum(bytes), 0) as "Total Bytes",
      coalesce(sum(packets), 0) as "Total Packets",
      max(start_time) as "Last Seen"
    from
      aws_vpc_flow_log
    where
      interface_id is not null
    group by
      interface_id,
      vpc_id,
      subnet_id,
      account_id,
      region
    order by
      "Records" desc
    limit 10;
  EOQ

  tags = {
    folder = "VPC"
  }
}


query "activity_dashboard_top_source_ips_by_traffic" {
  title       = "Top 10 Source IP Addresses by Traffic"
  description = "List the top 10 source IP addresses generating the most traffic."

  sql = <<-EOQ
    select
      src_addr as "Source IP",
      count(*) as "Records",
      coalesce(sum(bytes), 0) as "Total Bytes",
      coalesce(sum(packets), 0) as "Total Packets",
      max(start_time) as "Last Seen"
    from
      aws_vpc_flow_log
    where
      src_addr is not null
    group by
      src_addr
    order by
      "Records" desc
    limit 10;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "activity_dashboard_top_destination_ips_by_traffic" {
  title       = "Top 10 Destination IP Addresses by Traffic"
  description = "List the top 10 destination IP addresses generating the most traffic."

  sql = <<-EOQ
    select
      dst_addr as "Destination IP",
      count(*) as "Records",
      coalesce(sum(bytes), 0) as "Total Bytes",
      coalesce(sum(packets), 0) as "Total Packets",
      max(start_time) as "Last Seen"
    from
      aws_vpc_flow_log
    where
      dst_addr is not null
    group by
      dst_addr
    order by
      "Records" desc
    limit 10;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "activity_dashboard_top_source_ips_by_rejected_traffic" {
  title       = "Top 10 Source IP Addresses by Rejected Traffic"
  description = "List the top 10 source IP addresses with the most rejected traffic."

  sql = <<-EOQ
    select
      src_addr as "Source IP",
      count(*) as "Records",
      coalesce(sum(bytes), 0) as "Total Bytes",
      coalesce(sum(packets), 0) as "Total Packets",
      max(start_time) as "Last Rejected"
    from
      aws_vpc_flow_log
    where
      src_addr is not null
      and action = 'REJECT'
    group by
      src_addr
    order by
      "Records" desc
    limit 10;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "activity_dashboard_top_source_destination_pairs_by_packets" {
  title       = "Top 10 Source Destination Pairs by Packets"
  description = "List the top 10 source-destination pairs with the highest packet counts."

  sql = <<-EOQ
    select
      src_addr as "Source IP",
      dst_addr as "Destination IP",
      coalesce(sum(packets), 0) as "Total Packets",
      coalesce(sum(bytes), 0) as "Total Bytes",
      count(*) as "Records",
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

query "activity_dashboard_traffic_by_protocol" {
  title       = "Traffic by Protocol"
  description = "Distribution of record counts across different protocols."

  sql = <<-EOQ
    select
      case
        when protocol = 1 then 'ICMP'
        when protocol = 6 then 'TCP'
        when protocol = 17 then 'UDP'
        else 'Other'
      end as protocol_type,
      count(*) as "Records"
    from
      aws_vpc_flow_log
    where
      protocol is not null
    group by
      protocol_type
    order by
      "Records" desc;
  EOQ

  tags = {
    folder = "VPC"
  }
}

query "activity_dashboard_traffic_by_region" {
  title       = "Traffic by Region"
  description = "Distribution of record counts across different AWS regions."

  sql = <<-EOQ
    select
      region,
      count(*) as "Records"
    from
      aws_vpc_flow_log
    where
      region is not null
    group by
      region
    order by
      "Records" asc,
      region;
  EOQ

  tags = {
    folder = "VPC"
  }
}
