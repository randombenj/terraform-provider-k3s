terraform {
  required_providers {
    k3s = {
      source  = "hashicorp.com/edu/k3s"
    }
  }
}

provider "k3s" {
    user       = "root"
    private_key = file("~/.ssh/id_ed25519")
}

resource "k3s_installation" "k3s_install" {
    host    = "10.61.173.72"
}
