variable "region" {
  type    = string
  default = "us-west-2"
}

variable "profile" {
  description = "Null uses AWS_PROFILE / the AWS SDK credential chain. No credentials in tfvars."
  type        = string
  default     = null
  nullable    = true
}

variable "admin_cidr" {
  description = "Operator's single public IPv4 address, with /32. Required; no open SSH default."
  type        = string
  validation {
    condition     = can(cidrnetmask(var.admin_cidr)) && endswith(var.admin_cidr, "/32") && var.admin_cidr != "0.0.0.0/32"
    error_message = "Supply a nonzero operator IPv4 /32; broad SSH access is refused."
  }
}

variable "ssh_public_key" {
  description = "OpenSSH public key only. Private key remains on the operator's computer."
  type        = string
  validation {
    condition     = can(regex("^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]+( .*)?$", var.ssh_public_key))
    error_message = "Supply an OpenSSH public key, never a private key."
  }
}

variable "budget_email" {
  description = "Private alert recipient; supplied at apply, persisted only in protected local state."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.budget_email))
    error_message = "Supply a budget alert email address."
  }
}

variable "hostname" {
  description = "Optional DNS name already pointed to the static IP; empty selects dashed-IP.sslip.io."
  type        = string
  default     = ""
  validation {
    condition     = var.hostname == "" || can(regex("^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\\.[a-z]{2,}$", var.hostname))
    error_message = "Use a lowercase DNS hostname without scheme, port, path or wildcard."
  }
}
