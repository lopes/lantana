terraform {
  required_version = ">= 1.5"

  required_providers {
    vsphere = {
      source  = "hashicorp/vsphere"
      version = ">= 2.6"
    }
  }
}

provider "vsphere" {
  user                 = var.vsphere_user
  password             = var.vsphere_password
  vsphere_server       = var.vsphere_server
  allow_unverified_ssl = var.vsphere_allow_unverified_ssl
}

# --- SINGLE-NODE DEPLOYMENT ---
module "single_node" {
  source = "./modules/lantana-node"
  count  = var.deployment_mode == "single" ? 1 : 0

  vm_name          = "${var.operation_name}-sn-01"
  datacenter       = var.datacenter
  cluster          = var.cluster
  datastore        = var.datastore
  template         = var.vm_template
  resource_pool    = var.resource_pool
  folder           = var.vm_folder
  num_cpus         = var.single_node_cpus
  memory           = var.single_node_memory
  disk_size        = var.single_node_disk
  wan_network      = var.wan_network
  lan_network      = null # Single-node uses dummy interface
  ssh_public_key   = var.ssh_public_key
  admin_user       = "lantana"
}

# --- MULTI-NODE DEPLOYMENT ---
module "honeywall" {
  source = "./modules/lantana-node"
  count  = var.deployment_mode == "multi" ? 1 : 0

  vm_name          = "${var.operation_name}-honeywall-01"
  datacenter       = var.datacenter
  cluster          = var.cluster
  datastore        = var.datastore
  template         = var.vm_template
  resource_pool    = var.resource_pool
  folder           = var.vm_folder
  num_cpus         = 2
  memory           = 2048
  disk_size        = 20
  wan_network      = var.wan_network
  lan_network      = var.lan_network
  ssh_public_key   = var.ssh_public_key
  admin_user       = "lantana"
}

module "sensor" {
  source = "./modules/lantana-node"
  count  = var.deployment_mode == "multi" ? 1 : 0

  vm_name          = "${var.operation_name}-low-01"
  datacenter       = var.datacenter
  cluster          = var.cluster
  datastore        = var.datastore
  template         = var.vm_template
  resource_pool    = var.resource_pool
  folder           = var.vm_folder
  num_cpus         = 2
  memory           = 4096
  disk_size        = 40
  wan_network      = null
  lan_network      = var.lan_network
  ssh_public_key   = var.ssh_public_key
  admin_user       = "lantana"
}

module "collector" {
  source = "./modules/lantana-node"
  count  = var.deployment_mode == "multi" ? 1 : 0

  vm_name          = "${var.operation_name}-collector-01"
  datacenter       = var.datacenter
  cluster          = var.cluster
  datastore        = var.datastore
  template         = var.vm_template
  resource_pool    = var.resource_pool
  folder           = var.vm_folder
  num_cpus         = 2
  memory           = 4096
  disk_size        = 100 # Larger disk for datalake
  wan_network      = null
  lan_network      = var.lan_network
  ssh_public_key   = var.ssh_public_key
  admin_user       = "lantana"
}
