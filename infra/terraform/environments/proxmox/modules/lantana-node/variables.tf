variable "vm_name" {
  description = "Name of the virtual machine"
  type        = string
}

variable "node_name" {
  description = "Proxmox node name"
  type        = string
}

variable "template_vm_id" {
  description = "VM ID of the template to clone"
  type        = number
}

variable "datastore_id" {
  description = "Datastore for VM disks"
  type        = string
  default     = "local-lvm"
}

variable "num_cpus" {
  description = "Number of CPU cores"
  type        = number
  default     = 2
}

variable "memory" {
  description = "Memory in MB"
  type        = number
  default     = 4096
}

variable "disk_size" {
  description = "Disk size in GB"
  type        = number
  default     = 40
}

variable "wan_bridge" {
  description = "WAN bridge name (null to skip)"
  type        = string
  default     = null
}

variable "lan_bridge" {
  description = "LAN bridge name (null to skip)"
  type        = string
  default     = null
}

variable "user_data_file_id" {
  description = "Proxmox file ID for cloud-init userdata snippet"
  type        = string
}
