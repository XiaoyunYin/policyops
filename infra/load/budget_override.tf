# Copy to the load-only Terraform configuration directory. A count in the live
# configuration would move the account budget to an indexed resource address.
resource "aws_budgets_budget" "demo" {
  count = var.create_budget ? 1 : 0
}
