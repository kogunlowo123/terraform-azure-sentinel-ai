# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-15

### Added

- Initial release of the Azure Sentinel AI-powered SOC automation module.
- Log Analytics workspace provisioning with configurable SKU and retention.
- Microsoft Sentinel onboarding and workspace integration.
- Data connectors for Azure Active Directory, Azure Security Center, and Microsoft Defender ATP.
- Scheduled analytics rules with default detections for brute-force login, impossible travel, and suspicious PowerShell execution.
- Microsoft Security Incident alert rule for Cloud App Security.
- Automation rules for incident response workflows.
- SOAR playbooks via Logic Apps with HTTP triggers and AI-powered triage actions.
- Threat intelligence watchlists with configurable indicator items.
- Threat intelligence indicators for IP and domain-based IOCs.
- Comprehensive input validation for all variables.
