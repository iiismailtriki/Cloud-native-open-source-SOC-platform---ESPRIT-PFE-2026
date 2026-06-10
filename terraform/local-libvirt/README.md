# Local Libvirt Terraform Demo

This folder contains the Infrastructure as Code layer used for the local DevSecOps demo.

Terraform uses the `dmacvicar/libvirt` provider to define three local KVM/libvirt virtual machines:

- `soc-master` — k3s control-plane node
- `soc-worker1` — k3s worker node
- `soc-worker2` — k3s worker node

Cloud-init bootstraps the VMs with the Linux user, SSH access, base packages, and network configuration.

After the VMs are provisioned, AWX pulls the GitHub repository and runs the Ansible playbook:

`ansible/local-demo/local-demo.yml`

This separates the demo into two layers:

1. Terraform: creates the local infrastructure.
2. AWX/Ansible: configures and validates the SOC demo environment.

Terraform state files are intentionally excluded from Git.
