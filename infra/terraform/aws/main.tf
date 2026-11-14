resource "aws_lightsail_key_pair" "demo" {
  name       = "policyops-demo"
  public_key = var.ssh_public_key
}

resource "aws_lightsail_instance" "demo" {
  name              = "policyops-demo"
  availability_zone = "${var.region}a"
  blueprint_id      = "ubuntu_24_04"
  bundle_id         = "small_3_0"
  ip_address_type   = "ipv4"
  key_pair_name     = aws_lightsail_key_pair.demo.name
  user_data = templatefile("${path.module}/../../deploy/cloud-init.yaml.tftpl", {
    admin_cidr = var.admin_cidr
  })
}

resource "aws_lightsail_static_ip" "demo" {
  name = "policyops-demo"
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
    cidrs     = ["0.0.0.0/0"]
  }
}

resource "aws_budgets_budget" "demo" {
  name         = "policyops-monthly"
  budget_type  = "COST"
  limit_amount = "20"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
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
