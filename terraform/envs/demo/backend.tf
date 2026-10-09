terraform {
  backend "s3" {
    bucket       = "seks-tfstate"
    key          = "envs/demo/terraform.tfstate"
    region       = "us-east-1"
    use_lockfile = true # S3 native lock (Terraform 1.10+, no DynamoDB needed)
  }
}
