packer {
  required_version = "= 1.15.3"
  required_plugins {
    qemu = {
      version = "= 1.1.4"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

variable "source_image" { type = string }
variable "source_sha256" { type = string }
variable "seed_dir" { type = string }
variable "output_dir" { type = string }
variable "inventory_path" { type = string }
variable "ssh_key" { type = string }
variable "profile" { type = string }

source "qemu" "rocky" {
  accelerator       = "kvm"
  machine_type      = "q35"
  disk_image        = true
  iso_url           = var.source_image
  iso_checksum      = "sha256:${var.source_sha256}"
  disk_size         = "32768M"
  format            = "qcow2"
  disk_interface    = "virtio"
  net_device        = "virtio-net"
  cpus              = 4
  memory            = 8192
  headless          = true
  efi_boot          = true
  efi_firmware_code = "/usr/share/OVMF/OVMF_CODE_4M.fd"
  efi_firmware_vars = "/usr/share/OVMF/OVMF_VARS_4M.fd"
  efi_drop_efivars   = true
  cd_label          = "cidata"
  cd_files          = ["${var.seed_dir}/*"]
  ssh_username      = "packer"
  ssh_private_key_file = var.ssh_key
  ssh_timeout       = "15m"
  ssh_handshake_attempts = 30
  output_directory  = var.output_dir
  vm_name           = "image.qcow2"
  shutdown_command  = "sudo -n systemd-run --on-active=2s --unit=autonomous-image-seal --collect /usr/bin/python3 /mnt/packer/payload/guest.py seal"
  shutdown_timeout  = "5m"
  qemuargs = [
    ["-netdev", "user,id=user.0,restrict=on,hostfwd=tcp:127.0.0.1:{{ .SSHHostPort }}-:22"],
    ["-cpu", "host"],
    ["-serial", "file:${var.output_dir}/build.serial.log"]
  ]
}

build {
  sources = ["source.qemu.rocky"]
  provisioner "shell" {
    inline = ["sudo -n /usr/bin/python3 /mnt/packer/payload/guest.py install ${var.profile}"]
  }
  provisioner "file" {
    direction   = "download"
    source      = "/var/tmp/image-inventory.json"
    destination = var.inventory_path
  }
  provisioner "shell" {
    inline = ["sudo -n /usr/bin/python3 /mnt/packer/payload/guest.py check-seal"]
  }
}
