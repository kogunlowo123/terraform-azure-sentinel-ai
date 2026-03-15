output "workspace_id" {
  description = "The ID of the Log Analytics workspace"
  value       = module.sentinel.workspace_id
}

output "workspace_name" {
  description = "The name of the Log Analytics workspace"
  value       = module.sentinel.workspace_name
}

output "sentinel_id" {
  description = "The ID of the Sentinel onboarding resource"
  value       = module.sentinel.sentinel_id
}

output "analytics_rule_ids" {
  description = "Map of analytics rule names to their IDs"
  value       = module.sentinel.analytics_rule_ids
}

output "automation_rule_ids" {
  description = "Map of automation rule names to their IDs"
  value       = module.sentinel.automation_rule_ids
}

output "playbook_ids" {
  description = "Map of playbook names to their Logic App workflow IDs"
  value       = module.sentinel.playbook_ids
}

output "data_connector_ids" {
  description = "Map of enabled data connector IDs"
  value       = module.sentinel.data_connector_ids
}
