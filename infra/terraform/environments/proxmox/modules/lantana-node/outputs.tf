output "vm_ip" {
  description = "Primary IP address of the VM"
  value       = proxmox_virtual_environment_vm.node.ipv4_addresses[1][0]
}

output "vm_name" {
  description = "Name of the VM"
  value       = proxmox_virtual_environment_vm.node.name
}

output "vm_id" {
  description = "ID of the VM"
  value       = proxmox_virtual_environment_vm.node.vm_id
}
