mod "aws_vpc_flow_log_detections" {
  title         = "AWS VPC Flow Log Detections"
  description   = "Run detections and view dashboards for your AWS VPC Flow Logs to monitor and analyze network activity across your AWS accounts using Powerpipe and Tailpipe."
  color         = "#FF9900"
  documentation = file("./README.md")
  icon          = "/images/mods/turbot/aws-vpc-flow-log-detections.svg"
  categories    = ["aws", "security", "compliance", "logging"]
  database      = var.database

  opengraph {
    title       = "AWS VPC Flow Log Detections Mod for Powerpipe"
    description = "Run detections and view dashboards for your AWS VPC Flow Logs to monitor and analyze network activity across your AWS accounts using Powerpipe and Tailpipe."
    image       = "/images/mods/turbot/aws-vpc-flow-log-detections-social-graphic.png"
  }
} 