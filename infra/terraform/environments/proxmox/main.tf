terraform {
  required_version = ">= 1.5"

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = ">= 0.66"
    }
  }
}

provider "proxmox" {
  endpoint = var.proxmox_endpoint
  username = var.proxmox_username
  password = var.proxmox_password
  insecure = var.proxmox_insecure
}

# --- CLOUD-INIT (shared module) ---
module "cloud_init" {
  source = "../../modules/cloud-init"

  ssh_public_key = var.ssh_public_key
}

resource "proxmox_virtual_environment_file" "cloud_init" {
  content_type = "snippets"
  datastore_id = var.snippets_datastore
  node_name    = var.node_name

  source_raw {
    data      = module.cloud_init.userdata_raw
    file_name = "${var.operation_name}-cloud-init.yaml"
  }
}

# --- SINGLE-NODE DEPLOYMENT ---
module "single_node" {
  source = "./modules/lantana-node"
  count  = var.deployment_mode == "single" ? 1 : 0

  vm_name            = "${var.operation_name}-sn-01"
  node_name          = var.node_name
  template_vm_id     = var.template_vm_id
  datastore_id       = var.datastore
  num_cpus           = var.single_node_cpus
  memory             = var.single_node_memory
  disk_size          = var.single_node_disk
  wan_bridge         = var.wan_bridge
  lan_bridge         = null
  user_data_file_id  = proxmox_virtual_environment_file.cloud_init.id
}

# --- MULTI-NODE DEPLOYMENT ---
module "honeywall" {
  source = "./modules/lantana-node"
  count  = var.deployment_mode == "multi" ? 1 : 0

  vm_name            = "${var.operation_name}-honeywall-01"
  node_name          = var.node_name
  template_vm_id     = var.template_vm_id
  datastore_id       = var.datastore
  num_cpus           = 2
  memory             = 2048
  disk_size          = 20
  wan_bridge         = var.wan_bridge
  lan_bridge         = var.lan_bridge
  user_data_file_id  = proxmox_virtual_environment_file.cloud_init.id
}

module "sensor" {
  source = "./modules/lantana-node"
  count  = var.deployment_mode == "multi" ? 1 : 0

  vm_name            = "${var.operation_name}-low-01"
  node_name          = var.node_name
  template_vm_id     = var.template_vm_id
  datastore_id       = var.datastore
  num_cpus           = 2
  memory             = 4096
  disk_size          = 40
  wan_bridge         = null
  lan_bridge         = var.lan_bridge
  user_data_file_id  = proxmox_virtual_environment_file.cloud_init.id
}

module "collector" {
  source = "./modules/lantana-node"
  count  = var.deployment_mode == "multi" ? 1 : 0

  vm_name            = "${var.operation_name}-collector-01"
  node_name          = var.node_name
  template_vm_id     = var.template_vm_id
  datastore_id       = var.datastore
  num_cpus           = 2
  memory             = 4096
  disk_size          = 100
  wan_bridge         = null
  lan_bridge         = var.lan_bridge
  user_data_file_id  = proxmox_virtual_environment_file.cloud_init.id
}
