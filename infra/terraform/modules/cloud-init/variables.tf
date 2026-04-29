variable "admin_user" {
  description = "Admin username for the VM"
  type        = string
  default     = "lantana"
}

variable "ssh_public_key" {
  description = "SSH public key for the admin user"
  type        = string
}
