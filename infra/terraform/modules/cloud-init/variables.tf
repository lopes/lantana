variable "admin_user" {
  description = "Admin username for the VM"
  type        = string
  default     = "lantana"
}

variable "ssh_public_key" {
  description = "SSH public key for the admin user"
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
