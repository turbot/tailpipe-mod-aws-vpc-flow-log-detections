locals {
  mitre_attack_v161_ta0040_t1496_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_attack_technique_id = "T1496"
  })
}

benchmark "mitre_attack_v161_ta0040_t1496" {
  title         = "T1496 Resource Hijacking"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1496.md")
  children = [
    benchmark.mitre_attack_v161_ta0040_t1496_002
  ]

  tags = local.mitre_attack_v161_ta0040_t1496_common_tags
}

benchmark "mitre_attack_v161_ta0040_t1496_002" {
  title         = "T1496.002 Resource Hijacking: Bandwidth Hijacking"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1496_002.md")
  children = [
    detection.vpc_flow_connection_transferred_with_high_packet_count,
  ]

  tags = merge(local.mitre_attack_v161_ta0040_t1496_common_tags, {
    mitre_attack_technique_id = "T1496.002"
  })
}

