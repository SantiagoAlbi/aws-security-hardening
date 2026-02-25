variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "security-hardening"
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
  default     = "example@mail.com" # Agregar tu email
}

variable "enable_auto_remediation" {
  description = "Enable automatic remediation of security issues"
  type        = bool
  default     = false # Deshabilitado por seguridad, habilitar después
}
