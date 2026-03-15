resource "azurerm_resource_group" "test" {
  name     = "rg-sentinel-test"
  location = "eastus2"
}

module "test" {
  source = "../"

  name_prefix         = "sentinel-test"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name

  log_analytics_sku = "PerGB2018"
  retention_in_days = 90

  enable_aad_connector  = true
  enable_asc_connector  = true
  enable_mdatp_connector = false

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
    }
  ]

  enable_playbooks = true

  tags = {
    Environment = "test"
    Terraform   = "true"
  }
}
