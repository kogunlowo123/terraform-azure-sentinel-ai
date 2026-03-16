variable "name_prefix" {
  description = "Prefix for all resource names."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-]{2,23}$", var.name_prefix))
    error_message = "Name prefix must start with a letter, contain only alphanumeric characters and hyphens, and be 3-24 characters long."
  }
}

variable "location" {
  description = "Azure region for all resources."
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group."
  type        = string
}

variable "log_analytics_sku" {
  description = "SKU for the Log Analytics workspace."
  type        = string
  default     = "PerGB2018"

  validation {
    condition     = contains(["PerGB2018", "Free", "Standalone", "PerNode"], var.log_analytics_sku)
    error_message = "Log Analytics SKU must be one of: PerGB2018, Free, Standalone, PerNode."
  }
}

variable "retention_in_days" {
  description = "Data retention period in days for the Log Analytics workspace."
  type        = number
  default     = 90

  validation {
    condition     = var.retention_in_days >= 30 && var.retention_in_days <= 730
    error_message = "Retention must be between 30 and 730 days."
  }
}

variable "enable_aad_connector" {
  description = "Enable Azure Active Directory data connector."
  type        = bool
  default     = true
}

variable "enable_asc_connector" {
  description = "Enable Azure Security Center data connector."
  type        = bool
  default     = true
}

variable "enable_mdatp_connector" {
  description = "Enable Microsoft Defender ATP data connector."
  type        = bool
  default     = false
}

variable "analytics_rules" {
  description = "List of scheduled analytics rules for threat detection."
  type = list(object({
    name      = string
    severity  = string
    query     = string
    frequency = string
    lookback  = string
  }))
  default = [
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

  validation {
    condition     = alltrue([for rule in var.analytics_rules : contains(["High", "Medium", "Low", "Informational"], rule.severity)])
    error_message = "Each analytics rule severity must be one of: High, Medium, Low, Informational."
  }
}

variable "automation_rules" {
  description = "List of automation rules for automated incident response."
  type = list(object({
    name                 = string
    order                = number
    change_severity      = optional(string)
    condition_severities = list(string)
  }))
  default = [
    {
      name                 = "auto-escalate-high-severity"
      order                = 1
      change_severity      = null
      condition_severities = ["High"]
    }
  ]
}

variable "enable_playbooks" {
  description = "Enable SOAR playbooks (Logic Apps) for automated response."
  type        = bool
  default     = true
}

variable "playbook_configs" {
  description = "Configuration for SOAR playbooks."
  type = list(object({
    name             = string
    enable_ai_triage = bool
    ai_endpoint_url  = optional(string, "https://api.openai.com/v1/chat/completions")
  }))
  default = [
    {
      name             = "ai-triage-playbook"
      enable_ai_triage = true
      ai_endpoint_url  = "https://api.openai.com/v1/chat/completions"
    }
  ]
}

variable "watchlist_items" {
  description = "List of threat intelligence watchlist items."
  type = list(object({
    indicator   = string
    type        = string
    confidence  = number
    description = string
  }))
  default = []

  validation {
    condition     = alltrue([for item in var.watchlist_items : item.confidence >= 0 && item.confidence <= 100])
    error_message = "Confidence score must be between 0 and 100."
  }
}

variable "tags" {
  description = "Tags to apply to all resources."
  type        = map(string)
  default     = {}
}
