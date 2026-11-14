terraform {
  required_version = "= 1.15.8"
  # init MUST supply path outside the checkout; see docs/deployment.md.
  backend "local" {}
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.25.0"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = var.profile
  default_tags {
    tags = { Project = "PolicyOps", Purpose = "fictional-public-demo" }
  }
}
