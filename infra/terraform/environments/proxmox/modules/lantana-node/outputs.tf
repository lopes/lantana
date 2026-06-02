output "vm_ip" {
  description = "Primary IP address of the VM"
  # ipv4_addresses is per-NIC: [0] is loopback, [1] is the first real NIC (WAN
  # for single-node and honeywall; LAN for multi-node sensor/collector). The
  # inner [0] picks the first IPv4 on that NIC.
  value = proxmox_virtual_environment_vm.node.ipv4_addresses[1][0]
}

output "vm_name" {
  description = "Name of the VM"
  value       = proxmox_virtual_environment_vm.node.name
}

output "vm_id" {
  description = "ID of the VM"
  value       = proxmox_virtual_environment_vm.node.vm_id
}
