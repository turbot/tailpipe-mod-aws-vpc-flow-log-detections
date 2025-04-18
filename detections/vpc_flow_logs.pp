benchmark "vpc_flow_log_detections" {
  title       = "VPC Flow Log Detections"
  description = "This benchmark contains recommendations when scanning VPC flow logs."
  type        = "detection"
  children = [
    benchmark.data_transfer_detections,
    benchmark.port_detections,
    benchmark.protocol_detections
  ]

  tags = merge(local.vpc_flow_log_detections_common_tags, {
    type = "Benchmark"
  })
}
