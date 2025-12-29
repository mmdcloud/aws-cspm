variable "topic_name" {}
variable "kms_master_key_id" {
  type    = string
  default = null
}
variable "subscriptions" {
  type = list(object({
    protocol = string
    endpoint = string
  }))
}
variable "policy" {
  type    = string
  default = null    
}