variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "enable_guardduty" {
  description = "Enable GuardDuty"
  type        = bool
  default     = true
}

variable "enable_inspector" {
  description = "Enable Inspector"
  type        = bool
  default     = true
}

variable "enable_macie" {
  description = "Enable Macie"
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Enable AWS Config"
  type        = bool
  default     = true
}

variable "enable_access_analyzer" {
  description = "Enable IAM Access Analyzer"
  type        = bool
  default     = true
}

variable "auto_remediation_enabled" {
  description = "Enable auto-remediation"
  type        = bool
  default     = true
}

variable "notification_email" {
  description = "Email for security notifications"
  type        = string
}