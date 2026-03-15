###############################################################################
# Complete Example - Azure Sentinel AI
#
# This example deploys a fully configured Microsoft Sentinel with:
# - Log Analytics workspace with 90-day retention
# - Azure AD and Azure Security Center data connectors
# - Scheduled analytics rules for brute-force, impossible travel, and
#   suspicious PowerShell detection
# - Automation rules for auto-escalation of high-severity incidents
# - SOAR playbooks (Logic Apps) with AI-powered triage
# - Threat intelligence watchlist with sample indicators
###############################################################################

resource "azurerm_resource_group" "example" {
  name     = "rg-sentinel-complete"
  location = "eastus2"
}

module "sentinel" {
  source = "../../"

  name_prefix         = "sentinel-prod"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  # Log Analytics Configuration
  log_analytics_sku = "PerGB2018"
  retention_in_days = 90

  # Data Connectors
  enable_aad_connector   = true
  enable_asc_connector   = true
  enable_mdatp_connector = true

  # Analytics Rules - Threat Detection
  analytics_rules = [
    {
      name      = "brute-force-login-attempts"
      severity  = "High"
      query     = <<-QUERY
        SigninLogs
        | where ResultType == "50126"
        | summarize FailureCount = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
        | where FailureCount >= 10
        | project TimeGenerated, UserPrincipalName, IPAddress, FailureCount
      QUERY
      frequency = "PT1H"
      lookback  = "PT1H"
    },
    {
      name      = "impossible-travel-detection"
      severity  = "Medium"
      query     = <<-QUERY
        SigninLogs
        | where ResultType == 0
        | summarize Locations = make_set(Location), Count = count() by UserPrincipalName, bin(TimeGenerated, 1h)
        | where array_length(Locations) > 1
      QUERY
      frequency = "PT1H"
      lookback  = "PT24H"
    },
    {
      name      = "suspicious-powershell-execution"
      severity  = "High"
      query     = <<-QUERY
        SecurityEvent
        | where EventID == 4688
        | where Process has "powershell.exe" or Process has "pwsh.exe"
        | where CommandLine has_any ("-EncodedCommand", "-enc", "Invoke-Expression", "IEX", "DownloadString", "WebClient")
        | project TimeGenerated, Computer, Account, CommandLine
      QUERY
      frequency = "PT5M"
      lookback  = "PT1H"
    }
  ]

  # Automation Rules - Incident Response
  automation_rules = [
    {
      name                 = "auto-escalate-high-severity"
      order                = 1
      change_severity      = null
      condition_severities = ["High"]
    }
  ]

  # SOAR Playbooks
  enable_playbooks = true
  playbook_configs = [
    {
      name             = "ai-triage-playbook"
      enable_ai_triage = true
      ai_endpoint_url  = "https://api.openai.com/v1/chat/completions"
    }
  ]

  # Threat Intelligence Watchlist
  watchlist_items = [
    {
      indicator   = "198.51.100.23"
      type        = "ip"
      confidence  = 85
      description = "Known C2 server observed in phishing campaigns"
    },
    {
      indicator   = "malicious-domain.example.com"
      type        = "domain"
      confidence  = 90
      description = "Domain associated with credential harvesting"
    },
    {
      indicator   = "d41d8cd98f00b204e9800998ecf8427e"
      type        = "hash"
      confidence  = 95
      description = "File hash of known ransomware payload"
    }
  ]

  tags = {
    Environment = "production"
    Project     = "sentinel-soc"
    ManagedBy   = "terraform"
    CostCenter  = "security-operations"
  }
}
