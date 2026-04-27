# --- SINGLE-NODE OUTPUTS ---
output "single_node_ip" {
  description = "IP address of the single-node VM"
  value       = var.deployment_mode == "single" ? module.single_node[0].vm_ip : null
}

# --- MULTI-NODE OUTPUTS ---
output "honeywall_ip" {
  description = "WAN IP address of the honeywall VM"
  value       = var.deployment_mode == "multi" ? module.honeywall[0].vm_ip : null
}

output "sensor_ip" {
  description = "LAN IP address of the sensor VM"
  value       = var.deployment_mode == "multi" ? module.sensor[0].vm_ip : null
}

output "collector_ip" {
  description = "LAN IP address of the collector VM"
  value       = var.deployment_mode == "multi" ? module.collector[0].vm_ip : null
}

output "ssh_command" {
  description = "SSH command to connect to the primary node"
  value = var.deployment_mode == "single" ? (
    "ssh -p 60090 lantana@${module.single_node[0].vm_ip}"
    ) : (
    "ssh -p 60090 lantana@${module.honeywall[0].vm_ip}"
  )
}
