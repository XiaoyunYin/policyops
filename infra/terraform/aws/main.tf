# Lightsail names share one per-region namespace across resource types.
resource "aws_lightsail_key_pair" "demo" {
  name       = "policyops-demo-key${var.name_suffix}"
  public_key = var.ssh_public_key
}

resource "aws_lightsail_instance" "demo" {
  name              = "policyops-demo${var.name_suffix}"
  availability_zone = "${var.region}a"
  blueprint_id      = "ubuntu_24_04"
  bundle_id         = "small_3_0"
  ip_address_type   = "ipv4"
  key_pair_name     = aws_lightsail_key_pair.demo.name
  user_data = templatefile("${path.module}/../../deploy/bootstrap.sh.tftpl", {
    admin_cidr = var.admin_cidr
  })
}

resource "aws_lightsail_static_ip" "demo" {
  name = "policyops-demo-ip${var.name_suffix}"
}

resource "aws_lightsail_static_ip_attachment" "demo" {
  static_ip_name = aws_lightsail_static_ip.demo.name
  instance_name  = aws_lightsail_instance.demo.name
}

resource "aws_lightsail_instance_public_ports" "demo" {
  instance_name = aws_lightsail_instance.demo.name
  port_info {
    protocol  = "tcp"
    from_port = 22
    to_port   = 22
    cidrs     = [var.admin_cidr]
  }
  port_info {
    protocol  = "tcp"
    from_port = 80
    to_port   = 80
    cidrs     = ["0.0.0.0/0"]
  }
  port_info {
    protocol  = "tcp"
    from_port = 443
    to_port   = 443
    cidrs     = local.https_cidrs
  }
}

resource "aws_budgets_budget" "demo" {
  name         = "policyops-monthly${var.name_suffix}"
  budget_type  = "COST"
  limit_amount = "20"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  lifecycle {
    precondition {
      condition     = var.create_budget && var.name_suffix == ""
      error_message = "For a suffixed deployment, install the load budget override in a separate configuration directory and set create_budget=false."
    }
  }
  # Account-wide anomaly alarm, intentionally includes costs outside Lightsail.
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_email]
  }
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.budget_email]
  }
}

locals {
  https_cidrs = var.name_suffix == "" ? ["0.0.0.0/0"] : concat(
    [var.admin_cidr], [for ip in aws_lightsail_static_ip.loadgen : "${ip.ip_address}/32"]
  )
}

resource "aws_lightsail_instance" "loadgen" {
  count             = var.create_loadgen ? 1 : 0
  name              = "policyops-loadgen${var.name_suffix}"
  availability_zone = "${var.region}a"
  blueprint_id      = "ubuntu_24_04"
  bundle_id         = var.loadgen_bundle
  ip_address_type   = "ipv4"
  key_pair_name     = aws_lightsail_key_pair.demo.name
}

resource "aws_lightsail_static_ip" "loadgen" {
  count = var.create_loadgen ? 1 : 0
  name  = "policyops-loadgen-ip${var.name_suffix}"
}

resource "aws_lightsail_static_ip_attachment" "loadgen" {
  count          = var.create_loadgen ? 1 : 0
  static_ip_name = aws_lightsail_static_ip.loadgen[count.index].name
  instance_name  = aws_lightsail_instance.loadgen[count.index].name
}

resource "aws_lightsail_instance_public_ports" "loadgen" {
  count         = var.create_loadgen ? 1 : 0
  instance_name = aws_lightsail_instance.loadgen[count.index].name
  lifecycle {
    precondition {
      condition     = var.name_suffix != "" && !var.create_budget
      error_message = "The load generator requires a suffixed deployment with create_budget=false."
    }
  }
  port_info {
    protocol  = "tcp"
    from_port = 22
    to_port   = 22
    cidrs     = [var.admin_cidr]
  }
}
