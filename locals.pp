locals {
  vpc_flow_log_detections_common_tags = {
    category = "Detections",
    plugin   = "aws",
    service  = "AWS/VPC"
  }
}

locals {
  detection_sql_columns = <<-SQL
    tp_timestamp as timestamp,
    action as operation,
    interface_id as resource,
    src_addr as source_ip,
    src_port::varchar as source_port,
    dst_addr as destination_ip,
    dst_port::varchar as destination_port,
    case
      when protocol = 1 then 'ICMP (1)'
      when protocol = 6 then 'TCP (6)'
      when protocol = 17 then 'UDP (17)'
      else 'Other (' || protocol || ')'
    end as protocol,
    account_id,
    region,
    vpc_id,
    tp_id as source_id,
     -- Create new aliases to preserve original row data
    protocol as protocol_src,
    *
    exclude (account_id, protocol, region, vpc_id)
  SQL


  // Common display columns for detections
  detection_display_columns = [
    "timestamp",
    "operation",
    "resource",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "protocol",
    "account_id",
    "region",
    "vpc_id",
    "source_id"
  ]
}
