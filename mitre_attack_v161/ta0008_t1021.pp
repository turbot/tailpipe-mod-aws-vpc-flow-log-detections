locals {
  mitre_attack_v161_ta0008_t1021_common_tags = merge(local.mitre_attack_v161_ta0008_common_tags, {
    mitre_attack_technique_id = "T1021"
  })
}

benchmark "mitre_attack_v161_ta0008_t1021" {
  title         = "T1021 Remote Services"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0008_t1021.md")
  children = [
    detection.vpc_flow_connection_established_with_rdp,
    detection.vpc_flow_connection_established_with_ssh,
  ]

  tags = local.mitre_attack_v161_ta0008_t1021_common_tags
}

