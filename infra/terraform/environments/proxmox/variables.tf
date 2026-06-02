# --- PROXMOX CONNECTION ---
variable "proxmox_endpoint" {
  description = "Proxmox API endpoint (e.g. https://pve.example.com:8006)"
  type        = string
}

variable "proxmox_username" {
  description = "Proxmox username (e.g. root@pam)"
  type        = string
}

variable "proxmox_password" {
  description = "Proxmox password"
  type        = string
  sensitive   = true
}

variable "proxmox_insecure" {
  description = "Skip TLS certificate verification"
  type        = bool
  default     = false
}

# --- INFRASTRUCTURE ---
variable "node_name" {
  description = "Proxmox node to deploy VMs on"
  type        = string
}

variable "datastore" {
  description = "Proxmox datastore for VM disks (e.g. local-lvm)"
  type        = string
  default     = "local-lvm"
}

variable "snippets_datastore" {
  description = "Proxmox datastore for cloud-init snippets (must have snippets content type enabled)"
  type        = string
  default     = "local"
}

variable "template_vm_id" {
  description = "VM ID of the Debian 13 template to clone"
  type        = number
}

# --- NETWORKING ---
variable "wan_bridge" {
  description = "Proxmox bridge for WAN (internet-facing, e.g. vmbr0)"
  type        = string
  default     = "vmbr0"
}

variable "lan_bridge" {
  description = "Proxmox bridge for LAN (internal, multi-node only, e.g. vmbr1)"
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

variable "ssh_port" {
  description = "SSH admin port — operator-chosen random ephemeral port (49152–65535) per operation. Never 22 or 60090."
  type        = number

  validation {
    condition     = var.ssh_port >= 49152 && var.ssh_port <= 65535
    error_message = "ssh_port must be in the ephemeral range 49152–65535 per Lantana OPSEC. See docs/setup.md deployment contract."
  }
}

# --- SINGLE-NODE SIZING ---
variable "single_node_cpus" {
  description = "CPU cores for single-node VM"
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
