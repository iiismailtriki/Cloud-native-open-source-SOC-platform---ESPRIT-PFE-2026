terraform {
  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "0.7.6"
    }
  }
}

provider "libvirt" {
  uri = "qemu:///system"
}

resource "libvirt_volume" "base" {
  name   = "ubuntu-24.04-base"
  pool   = "default"
  source = "/var/lib/libvirt/images/ubuntu-24.04-base.qcow2"
  format = "qcow2"
}

# --- MASTER ---
resource "libvirt_volume" "master" {
  name           = "soc-master.qcow2"
  pool           = "default"
  base_volume_id = libvirt_volume.base.id
  size           = 32212254720
}

resource "libvirt_cloudinit_disk" "master" {
  name      = "master-cloudinit.iso"
  pool      = "default"
  user_data = templatefile("${path.module}/cloud-init/master.yml", {})
}

resource "libvirt_domain" "master" {
  name   = "soc-master"
  memory = 8192
  vcpu   = 4
  cloudinit = libvirt_cloudinit_disk.master.id
  network_interface {
    network_name   = "default"
    wait_for_lease = true
  }
  disk { volume_id = libvirt_volume.master.id }
  console {
    type        = "pty"
    target_type = "serial"
    target_port = "0"
  }
}

# --- WORKER1 ---
resource "libvirt_volume" "worker1" {
  name           = "soc-worker1.qcow2"
  pool           = "default"
  base_volume_id = libvirt_volume.base.id
  size           = 21474836480
}

resource "libvirt_cloudinit_disk" "worker1" {
  name      = "worker1-cloudinit.iso"
  pool      = "default"
  user_data = templatefile("${path.module}/cloud-init/worker.yml", { hostname = "worker1", ip_address = "192.168.122.10" })
}

resource "libvirt_domain" "worker1" {
  name   = "soc-worker1"
  memory = 4096
  vcpu   = 2
  cloudinit = libvirt_cloudinit_disk.worker1.id
  network_interface {
    network_name   = "default"
    wait_for_lease = true
  }
  disk { volume_id = libvirt_volume.worker1.id }
  console {
    type        = "pty"
    target_type = "serial"
    target_port = "0"
  }
}

# --- WORKER2 ---
resource "libvirt_volume" "worker2" {
  name           = "soc-worker2.qcow2"
  pool           = "default"
  base_volume_id = libvirt_volume.base.id
  size           = 21474836480
}

resource "libvirt_cloudinit_disk" "worker2" {
  name      = "worker2-cloudinit.iso"
  pool      = "default"
  user_data = templatefile("${path.module}/cloud-init/worker.yml", { hostname = "worker2", ip_address = "192.168.122.95" })
}

resource "libvirt_domain" "worker2" {
  name   = "soc-worker2"
  memory = 4096
  vcpu   = 2
  cloudinit = libvirt_cloudinit_disk.worker2.id
  network_interface {
    network_name   = "default"
    wait_for_lease = true
  }
  disk { volume_id = libvirt_volume.worker2.id }
  console {
    type        = "pty"
    target_type = "serial"
    target_port = "0"
  }
}


output "master_ip"  { value = "192.168.122.35" }
output "worker1_ip" { value = "192.168.122.10" }
output "worker2_ip" { value = "192.168.122.95" }
