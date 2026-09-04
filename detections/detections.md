# Detection & DLP pack (Microsoft Sentinel / Defender KQL)

A small library of analytic rules and hunting queries written for the Microsoft security stack
named in the role (Sentinel, Defender, Email Gateway, Netskope via Sentinel connectors). Each entry
has the KQL, the intent, and **tuning notes**, because the role is explicit about *tuning and
enabling policies in response to incidents and general enhancements*.

> Illustrative. Table and column names follow Microsoft Sentinel / Defender XDR schemas; thresholds
> are starting points to be tuned against a real environment.

---

## Data Loss Prevention (4)

### DLP-1 — Large data upload to an unsanctioned / personal cloud app
Detects potential exfiltration to personal storage (a core DLP use case across cloud environments).
```kql
CloudAppEvents
| where Timestamp > ago(1h)
| where ActionType in ("FileUploaded","FileDownloaded")
| where isnotempty(AccountObjectId)
| extend App = tostring(RawEventData.ApplicationName)
| where App has_any ("Google Drive","Dropbox","personal","Consumer","MEGA","WeTransfer")
| summarize Uploads=count(), MB=round(sum(todouble(RawEventData.FileSize))/1048576,1) by AccountUpn=AccountDisplayName, App, bin(Timestamp,15m)
| where MB > 50 or Uploads > 100
```
**Tuning:** allow-list sanctioned tenants; exclude backup service accounts; raise MB threshold per role. In Netskope, back this with an inline policy that blocks upload of files tagged as classified.

### DLP-2 — Sensitive data emailed to an external domain
```kql
EmailEvents
| where Timestamp > ago(1h)
| where SenderFromDomain in ("yourorg.com")
| where RecipientEmailAddress !endswith "@yourorg.com"
| join kind=inner (EmailAttachmentInfo | where FileType in ("xlsx","csv","docx","pdf")) on NetworkMessageId
| where AttachmentCount > 0
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, FileName, FileType
```
**Tuning:** integrate with Purview sensitivity labels to fire only on Confidential/Restricted labels; suppress known partner domains; pair with Email Gateway rule for outbound blocking.

### DLP-3 — Mass file download from SharePoint / OneDrive (staging for exfil)
```kql
OfficeActivity
| where TimeGenerated > ago(1h)
| where Operation in ("FileDownloaded","FileSyncDownloadedFull")
| summarize Downloads=count(), Files=dcount(OfficeObjectId) by UserId, bin(TimeGenerated, 10m)
| where Downloads > 200 or Files > 150
```
**Tuning:** baseline per user with `series_decompose_anomalies` before alerting; exclude migration/service accounts.

### DLP-4 — Mass file copy to removable / USB media
```kql
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType == "FileCreated"
| where FolderPath has_any (@"\Removable", "USB", @"E:\", @"F:\")
| summarize Files=count(), MB=round(sum(FileSize)/1048576,1) by DeviceName, InitiatingProcessAccountName, bin(Timestamp,10m)
| where Files > 50 or MB > 100
```
**Tuning:** enforce with Defender for Endpoint device control; alert only where USB write is not already blocked by policy.

---

## Identity / Access (3)
### ID-1 — Impossible travel / atypical sign-in
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| summarize Countries=dcount(LocationDetails.countryOrRegion), locs=make_set(LocationDetails.countryOrRegion) by UserPrincipalName, bin(TimeGenerated,1h)
| where Countries > 1
```
**Tuning:** exclude VPN egress ranges and known travel; prefer the built-in anomaly connectors as the primary, use this as hunting.

### ID-2 — Password spray (many accounts, few attempts each, one source)
```kql
SigninLogs
| where TimeGenerated > ago(1h) and ResultType != 0
| summarize Targets=dcount(UserPrincipalName), Fails=count() by IPAddress, bin(TimeGenerated,15m)
| where Targets >= 10 and Fails >= 20
```
**Tuning:** allow-list corporate NAT IPs; escalate to P1 if any success from the same IP follows.

### ID-3 — New privileged role assignment outside change window
```kql
AuditLogs
| where OperationName has "Add member to role"
| extend Role = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where Role has_any ("Admin","Global","Security")
```
**Tuning:** correlate with the change/intake queue (SET Watchtower) so expected changes auto-close.

---

## Endpoint / Malware (3)
### EP-1 — Defender detection with auto-isolation trigger
```kql
DeviceEvents
| where Timestamp > ago(1h)
| where ActionType == "AntivirusDetection"
| project Timestamp, DeviceName, ThreatName = tostring(AdditionalFields.ThreatName), Severity = tostring(AdditionalFields.WasRemediated)
```
**Tuning:** raise to P1 and trigger isolation playbook for `Severity == High` on servers.

### EP-2 — Suspicious LOLBin execution (living off the land)
```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ ("powershell.exe","certutil.exe","mshta.exe","rundll32.exe")
| where ProcessCommandLine has_any ("-enc","DownloadString","http","FromBase64String")
```
**Tuning:** allow-list signed admin scripts; feed hits to hunting, not straight to alert.

### EP-3 — Malware protection agent unhealthy (ties to Run Activity)
```kql
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == "scid-2010"   // real-time protection state
| where IsApplicable == 1 and IsCompliant == 0
| project DeviceName, ConfigurationId, Timestamp
```
**Tuning:** this is a *health* signal, not a threat; route to the tooling-health queue so a silent AV is fixed fast.

---

## Email Gateway (2)
### MG-1 — Spike in blocked outbound mail (possible compromised mailbox)
```kql
EmailEvents
| where Timestamp > ago(1h) and EmailDirection == "Outbound"
| where DeliveryAction == "Blocked"
| summarize Blocked=count() by SenderFromAddress, bin(Timestamp,15m)
| where Blocked > 25
```

### MG-2 — Phishing campaign to multiple recipients (same subject/sender)
```kql
EmailEvents
| where Timestamp > ago(2h) and ThreatTypes has "Phish"
| summarize Recipients=dcount(RecipientEmailAddress) by SenderFromAddress, Subject
| where Recipients >= 5
```

---

## Tool Health (2)  — the "keep the lights green" detections
### TH-1 — Sentinel data connector stopped ingesting
```kql
Usage
| where TimeGenerated > ago(6h)
| summarize LastSeen = max(TimeGenerated) by DataType
| extend MinutesSilent = datetime_diff("minute", now(), LastSeen)
| where MinutesSilent > 15
```
**Why it matters:** a connector that quietly dies means detections silently stop firing. This is exactly what SET Watchtower surfaces on the dashboard.

### TH-2 — Analytic rule failing to run
```kql
SentinelHealth
| where TimeGenerated > ago(24h)
| where OperationName == "Scheduled analytics rule run" and Status != "Success"
| project TimeGenerated, SentinelResourceName, Status, Description
```
**Tuning:** page on repeated failures of high-value rules; auto-open an INC in the intake queue.
