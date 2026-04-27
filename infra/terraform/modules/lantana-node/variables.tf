variable "vm_name" {
  description = "Name of the virtual machine"
  type        = string
}

variable "datacenter" {
  description = "vSphere datacenter name"
  type        = string
}

variable "cluster" {
  description = "vSphere cluster name"
  type        = string
}

variable "datastore" {
  description = "vSphere datastore name"
  type        = string
}

variable "template" {
  description = "VM template to clone"
  type        = string
}

variable "resource_pool" {
  description = "vSphere resource pool"
  type        = string
  default     = ""
}

variable "folder" {
  description = "VM folder"
  type        = string
  default     = ""
}

variable "num_cpus" {
  description = "Number of vCPUs"
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

variable "wan_network" {
  description = "WAN port group name (null to skip)"
  type        = string
  default     = null
}

variable "lan_network" {
  description = "LAN port group name (null to skip)"
  type        = string
  default     = null
}

variable "ssh_public_key" {
  description = "SSH public key for admin user"
  type        = string
}

variable "admin_user" {
  description = "Admin username"
  type        = string
  default     = "lantana"
}
