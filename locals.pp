locals {
  vpc_flow_log_detections_common_tags = {
    category = "Detections",
    plugin   = "aws",
    service  = "AWS/VPC"
  }
}

locals {
  detection_sql_columns = <<-SQL
      tp_id as id,
      tp_timestamp as time,
      account_id as account_id,
      region as region,
      vpc_id as vpc_id,
      src_addr as source_ip,
      src_port as source_port,
      dst_addr as destination_ip,
      dst_port as destination_port,
      *
    SQL


  // Common display columns for detections
  vpc_flow_log_display_columns = [
    "time",
    "severity",
    "source_ip",
    "destination_ip",
    "destination_port",
    "protocol",
    "bytes",
    "region",
    "account_id"
  ]
}
