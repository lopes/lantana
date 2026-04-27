output "vm_ip" {
  description = "Primary IP address of the VM"
  value       = vsphere_virtual_machine.node.default_ip_address
}

output "vm_name" {
  description = "Name of the VM"
  value       = vsphere_virtual_machine.node.name
}

output "vm_id" {
  description = "ID of the VM"
  value       = vsphere_virtual_machine.node.id
}
