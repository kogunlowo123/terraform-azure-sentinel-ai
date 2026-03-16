output "workspace_id" {
  description = "The ID of the Log Analytics workspace."
  value       = azurerm_log_analytics_workspace.sentinel.id
}

output "workspace_name" {
  description = "The name of the Log Analytics workspace."
  value       = azurerm_log_analytics_workspace.sentinel.name
}

output "sentinel_id" {
  description = "The ID of the Sentinel onboarding resource."
  value       = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.id
}

output "analytics_rule_ids" {
  description = "Map of analytics rule names to their IDs."
  value       = { for k, v in azurerm_sentinel_alert_rule_scheduled.rules : k => v.id }
}

output "automation_rule_ids" {
  description = "Map of automation rule names to their IDs."
  value       = { for k, v in azurerm_sentinel_automation_rule.rules : k => v.id }
}

output "playbook_ids" {
  description = "Map of playbook names to their Logic App workflow IDs."
  value       = { for k, v in azurerm_logic_app_workflow.playbooks : k => v.id }
}

output "data_connector_ids" {
  description = "Map of enabled data connector IDs."
  value = {
    aad   = var.enable_aad_connector ? azurerm_sentinel_data_connector_azure_active_directory.aad[0].id : null
    asc   = var.enable_asc_connector ? azurerm_sentinel_data_connector_azure_security_center.asc[0].id : null
    mdatp = var.enable_mdatp_connector ? azurerm_sentinel_data_connector_microsoft_defender_advanced_threat_protection.mdatp[0].id : null
  }
}
