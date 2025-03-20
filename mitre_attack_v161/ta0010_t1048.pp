locals {
  mitre_attack_v161_ta0010_t1048_common_tags = merge(local.mitre_attack_v161_ta0010_common_tags, {
    mitre_attack_technique_id = "T1048"
  })
}

benchmark "mitre_attack_v161_ta0010_t1048" {
  title         = "T1048 Exfiltration Over Alternative Protocol"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0010_t1048.md")
  children = [
    detection.vpc_flow_connection_established_with_non_standard_web_ports,
    detection.vpc_flow_connection_transferred_with_high_volume,
  ]

  tags = local.mitre_attack_v161_ta0010_t1048_common_tags
}
