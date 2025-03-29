
terraform {

  required_providers {
    aws = {
      source  = "hashicorp/aws"
    }

    random = {
      source  = "hashicorp/random"
    }

    tls = {
      source  = "hashicorp/tls"
    }
  }

#   required_version = "~> 1.3"
}
