terraform {
  required_version = "~> 0.12.0"
}

provider "aws" {
  version = "~> 2.12.0"
  profile = "ev-prod-mumbai"
  region  = "us-east-1"
}

variable "name" {}

module "fargate" {
  source = "../"

  vpc_create_nat = false

  name = var.name

  vpc_cidr = "10.1.0.0/16"

  services = {
    api = {
      task_definition = "api.json"
      container_port  = 3000
      cpu             = "256"
      memory          = "512"
      replicas        = 3

      registry_retention_count = 15
      logs_retention_days      = 14
    }
  }
}
