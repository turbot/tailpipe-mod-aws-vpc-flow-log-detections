locals {
  vpc_flow_log_detections_common_tags = {
    service       = "aws_vpc_flow_logs",
    plugin        = "aws",
    category      = "AWS/VPC",
  }
}

locals {
  detection_sql_columns = <<-EOQ
    tp_id as id,
    tp_timestamp as time,
    src_addr as source_ip,
    dst_addr as destination_ip,
    dst_port as destination_port,
    protocol,
  EOQ

  // Common display columns for detections
  flow_log_detection_display_columns = [
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