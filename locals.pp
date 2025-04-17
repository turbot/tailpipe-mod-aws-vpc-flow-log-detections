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
    vpc_id as resource,
    src_addr as actor,
    tp_source_ip as source_ip,
    account_id,
    region,
    tp_id as source_id,
    *
    exclude (account_id, region)
  SQL


  // Common display columns for detections
  detection_display_columns = [
    "timestamp",
    "operation",
    "resource",
    "actor",
    "source_ip",
    "account_id",
    "region",
    "source_id"
  ]
}
