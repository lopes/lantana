terraform {
  required_providers {
    proxmox = {
      source = "bpg/proxmox"
    }
  }
}

resource "proxmox_virtual_environment_vm" "node" {
  name      = var.vm_name
  node_name = var.node_name

  clone {
    vm_id = var.template_vm_id
    full  = true
  }

  cpu {
    cores   = var.num_cpus
    sockets = 1
    type    = "x86-64-v2-AES"
  }

  memory {
    dedicated = var.memory
  }

  disk {
    datastore_id = var.datastore_id
    interface    = "scsi0"
    size         = var.disk_size
  }

  # WAN NIC (if provided)
  dynamic "network_device" {
    for_each = var.wan_bridge != null ? [1] : []
    content {
      bridge = var.wan_bridge
      model  = "virtio"
    }
  }

  # LAN NIC (if provided)
  dynamic "network_device" {
    for_each = var.lan_bridge != null ? [1] : []
    content {
      bridge = var.lan_bridge
      model  = "virtio"
    }
  }

  initialization {
    user_data_file_id = var.user_data_file_id

    ip_config {
      ipv4 {
        address = "dhcp"
      }
    }
  }

  operating_system {
    type = "l26"
  }
}
