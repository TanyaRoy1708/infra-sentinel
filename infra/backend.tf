terraform {
  backend "s3" {
    bucket         = "YOUR_TERRAFORM_STATE_BUCKET_NAME"
    key            = "sentinel/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "YOUR_DYNAMODB_TABLE_NAME"
    encrypt        = true
  }
}
