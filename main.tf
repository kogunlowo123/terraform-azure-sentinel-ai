###############################################################################
# Azure Sentinel (Microsoft Sentinel) with AI-Powered SOC Automation
###############################################################################

resource "azurerm_log_analytics_workspace" "sentinel" {
  name                = "${var.name_prefix}-law"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = var.log_analytics_sku
  retention_in_days   = var.retention_in_days

  tags = var.tags
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id                 = azurerm_log_analytics_workspace.sentinel.id
  customer_managed_key_enabled = false
}

###############################################################################
# Data Connectors
###############################################################################

resource "azurerm_sentinel_data_connector_azure_active_directory" "aad" {
  count = var.enable_aad_connector ? 1 : 0

  name                       = "${var.name_prefix}-aad-connector"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
}

resource "azurerm_sentinel_data_connector_azure_security_center" "asc" {
  count = var.enable_asc_connector ? 1 : 0

  name                       = "${var.name_prefix}-asc-connector"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
}

resource "azurerm_sentinel_data_connector_microsoft_defender_advanced_threat_protection" "mdatp" {
  count = var.enable_mdatp_connector ? 1 : 0

  name                       = "${var.name_prefix}-mdatp-connector"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
}

###############################################################################
# Scheduled Analytics Rules
###############################################################################

resource "azurerm_sentinel_alert_rule_scheduled" "rules" {
  for_each = { for rule in var.analytics_rules : rule.name => rule }

  name                       = each.value.name
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  display_name               = each.value.name
  severity                   = each.value.severity
  query                      = each.value.query
  query_frequency            = each.value.frequency
  query_period               = each.value.lookback
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  enabled                    = true

  suppression_enabled  = false
  suppression_duration = "PT5H"

  incident_configuration {
    create_incident = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
    }
  }
}

###############################################################################
# Microsoft Security Incident Alert Rule
###############################################################################

resource "azurerm_sentinel_alert_rule_ms_security_incident" "ms_security" {
  name                       = "${var.name_prefix}-ms-security-incidents"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  display_name               = "Create incidents from Microsoft security alerts"
  product_filter             = "Microsoft Cloud App Security"
  severity_filter            = ["High", "Medium"]
  enabled                    = true
}

###############################################################################
# Automation Rules
###############################################################################

resource "azurerm_sentinel_automation_rule" "rules" {
  for_each = { for idx, rule in var.automation_rules : rule.name => rule }

  name                       = each.value.name
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  display_name               = each.value.name
  order                      = each.value.order
  enabled                    = true

  dynamic "action_incident" {
    for_each = lookup(each.value, "change_severity", null) != null ? [1] : []
    content {
      order    = 1
      severity = each.value.change_severity
    }
  }

  condition_json = jsonencode([
    {
      conditionType       = "Property"
      conditionProperties = {
        propertyName   = "IncidentSeverity"
        operator       = "Equals"
        propertyValues = each.value.condition_severities
      }
    }
  ])
}

###############################################################################
# SOAR Playbooks (Logic Apps)
###############################################################################

resource "azurerm_logic_app_workflow" "playbooks" {
  for_each = var.enable_playbooks ? { for pb in var.playbook_configs : pb.name => pb } : {}

  name                = "${var.name_prefix}-${each.value.name}"
  location            = var.location
  resource_group_name = var.resource_group_name

  workflow_parameters = {
    "$connections" = jsonencode({
      defaultValue = {}
      type         = "Object"
    })
  }

  parameters = {
    "$connections" = jsonencode({})
  }

  tags = var.tags
}

resource "azurerm_logic_app_trigger_http_request" "playbook_triggers" {
  for_each = var.enable_playbooks ? { for pb in var.playbook_configs : pb.name => pb } : {}

  name         = "When_a_Sentinel_incident_is_created"
  logic_app_id = azurerm_logic_app_workflow.playbooks[each.key].id

  schema = jsonencode({
    type = "object"
    properties = {
      incidentId = { type = "string" }
      severity   = { type = "string" }
      title      = { type = "string" }
      description = { type = "string" }
    }
  })
}

resource "azurerm_logic_app_action_http" "ai_triage" {
  for_each = var.enable_playbooks ? {
    for pb in var.playbook_configs : pb.name => pb if pb.enable_ai_triage
  } : {}

  name         = "AI_Powered_Triage"
  logic_app_id = azurerm_logic_app_workflow.playbooks[each.key].id

  method = "POST"
  uri    = each.value.ai_endpoint_url

  headers = {
    "Content-Type" = "application/json"
  }

  body = jsonencode({
    incident_data = "@triggerBody()"
    action        = "triage_and_classify"
  })
}

###############################################################################
# Watchlists (Threat Intelligence)
###############################################################################

resource "azurerm_sentinel_watchlist" "threat_intel" {
  count = length(var.watchlist_items) > 0 ? 1 : 0

  name                       = "${var.name_prefix}-threat-intel-watchlist"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  display_name               = "Threat Intelligence Watchlist"
  description                = "AI-curated threat intelligence indicators"
  item_search_key            = "indicator"
  labels                     = ["ThreatIntel", "AI-Curated"]
}

resource "azurerm_sentinel_watchlist_item" "items" {
  for_each = { for idx, item in var.watchlist_items : item.indicator => item }

  watchlist_id = azurerm_sentinel_watchlist.threat_intel[0].id

  properties = {
    indicator   = each.value.indicator
    type        = each.value.type
    confidence  = each.value.confidence
    description = each.value.description
  }
}

###############################################################################
# Threat Intelligence Indicators
###############################################################################

resource "azurerm_sentinel_threat_intelligence_indicator" "indicators" {
  for_each = { for idx, item in var.watchlist_items : item.indicator => item if item.type == "ip" || item.type == "domain" }

  workspace_id   = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  pattern_type   = each.value.type == "ip" ? "ipv4-addr" : "domain-name"
  pattern        = each.value.type == "ip" ? "[ipv4-addr:value = '${each.value.indicator}']" : "[domain-name:value = '${each.value.indicator}']"
  display_name   = "TI-${each.value.indicator}"
  description    = each.value.description
  validate_from_utc = "2024-01-01T00:00:00Z"
  source         = "AI-Curated Threat Intelligence"
  confidence     = each.value.confidence

  threat_types = ["malicious-activity"]
}
