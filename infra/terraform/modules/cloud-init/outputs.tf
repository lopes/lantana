output "userdata_raw" {
  description = "Rendered cloud-init userdata (plain text)"
  value       = local.userdata
}

output "userdata_base64" {
  description = "Rendered cloud-init userdata (base64-encoded)"
  value       = base64encode(local.userdata)
}
