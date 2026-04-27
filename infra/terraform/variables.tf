# --- VSPHERE CONNECTION ---
variable "vsphere_server" {
  description = "vSphere server hostname or IP"
  type        = string
}

variable "vsphere_user" {
  description = "vSphere username"
  type        = string
}

variable "vsphere_password" {
  description = "vSphere password"
  type        = string
  sensitive   = true
}

variable "vsphere_allow_unverified_ssl" {
  description = "Allow unverified SSL connections to vSphere"
  type        = bool
  default     = false
}

# --- INFRASTRUCTURE ---
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

variable "resource_pool" {
  description = "vSphere resource pool name"
  type        = string
  default     = ""
}

variable "vm_folder" {
  description = "vSphere VM folder"
  type        = string
  default     = "lantana"
}

variable "vm_template" {
  description = "Debian 13 VM template name to clone"
  type        = string
}

# --- NETWORKING ---
variable "wan_network" {
  description = "vSphere port group for WAN (internet-facing)"
  type        = string
}

variable "lan_network" {
  description = "vSphere port group for LAN (internal, multi-node only)"
  type        = string
  default     = null
}

# --- DEPLOYMENT ---
variable "operation_name" {
  description = "Operation name prefix for VM naming"
  type        = string
  default     = "lantana"
}

variable "deployment_mode" {
  description = "Deployment mode: single or multi"
  type        = string
  default     = "single"

  validation {
    condition     = contains(["single", "multi"], var.deployment_mode)
    error_message = "deployment_mode must be 'single' or 'multi'"
  }
}

variable "ssh_public_key" {
  description = "SSH public key for the lantana admin user"
  type        = string
}

# --- SINGLE-NODE SIZING ---
variable "single_node_cpus" {
  description = "vCPUs for single-node VM"
  type        = number
  default     = 2
}

variable "single_node_memory" {
  description = "Memory (MB) for single-node VM"
  type        = number
  default     = 4096
}

variable "single_node_disk" {
  description = "Disk size (GB) for single-node VM"
  type        = number
  default     = 60
}
