data "vsphere_datacenter" "dc" {
  name = var.datacenter
}

data "vsphere_compute_cluster" "cluster" {
  name          = var.cluster
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_datastore" "ds" {
  name          = var.datastore
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_virtual_machine" "template" {
  name          = var.template
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_network" "wan" {
  count         = var.wan_network != null ? 1 : 0
  name          = var.wan_network
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_network" "lan" {
  count         = var.lan_network != null ? 1 : 0
  name          = var.lan_network
  datacenter_id = data.vsphere_datacenter.dc.id
}

resource "vsphere_virtual_machine" "node" {
  name             = var.vm_name
  resource_pool_id = data.vsphere_compute_cluster.cluster.resource_pool_id
  datastore_id     = data.vsphere_datastore.ds.id
  folder           = var.folder

  num_cpus = var.num_cpus
  memory   = var.memory

  guest_id = data.vsphere_virtual_machine.template.guest_id

  # WAN NIC (if provided)
  dynamic "network_interface" {
    for_each = var.wan_network != null ? [1] : []
    content {
      network_id = data.vsphere_network.wan[0].id
    }
  }

  # LAN NIC (if provided)
  dynamic "network_interface" {
    for_each = var.lan_network != null ? [1] : []
    content {
      network_id = data.vsphere_network.lan[0].id
    }
  }

  disk {
    label            = "disk0"
    size             = var.disk_size
    thin_provisioned = true
  }

  clone {
    template_uuid = data.vsphere_virtual_machine.template.id

    customize {
      linux_options {
        host_name = var.vm_name
        domain    = "lantana.local"
      }

      # Primary NIC
      network_interface {}

      # Second NIC (if LAN provided alongside WAN)
      dynamic "network_interface" {
        for_each = var.wan_network != null && var.lan_network != null ? [1] : []
        content {}
      }
    }
  }

  extra_config = {
    "guestinfo.userdata" = base64encode(templatefile("${path.module}/cloud-init.yaml.tftpl", {
      admin_user     = var.admin_user
      ssh_public_key = var.ssh_public_key
    }))
    "guestinfo.userdata.encoding" = "base64"
  }
}
