locals {
  hostname = var.hostname != "" ? var.hostname : "${replace(aws_lightsail_static_ip.demo.ip_address, ".", "-")}.sslip.io"
}

output "static_ip" {
  value = aws_lightsail_static_ip.demo.ip_address
}

output "hostname" {
  value = local.hostname
}

output "url" {
  value = "https://${local.hostname}"
}
