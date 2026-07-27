# Native TVM Workbook Query Pack

This folder provides a directly runnable equivalent of every query embedded in `MDETVM-KEV-Workbook-Native.json`. Run each file in **Microsoft Defender > Hunting > Advanced hunting**. Workbook parameter placeholders are replaced with editable dynamic arrays in queries 06 through 09.

The workbook has 13 query-backed components:

| Workbook component | Visualization | Standalone query | Result columns |
| --- | --- | --- | --- |
| Device filter | Parameter list | `01-Filter-Devices.kql` | `DeviceName` |
| CVE ID filter | Parameter list | `02-Filter-CVE-Ids.kql` | `CveId` |
| CISA vulnerability name filter | Parameter list | `03-Filter-CISA-Vulnerability-Names.kql` | `VulnerabilityName` |
| CISA vendor filter | Parameter list | `04-Filter-CISA-Vendors.kql` | `VendorProject` |
| CISA product filter | Parameter list | `05-Filter-CISA-Products.kql` | `Product` |
| KEV exposure summary | Tiles | `06-KEV-Exposure-Summary.kql` | `Metric`, `Value` |
| Active KEV findings | Table | `07-Active-KEV-Findings.kql` | Device, CVE, CISA, software, severity, due-date, and update fields |
| Top 10 devices by KEV count | Bar chart | `08-Top-Devices-by-KEV.kql` | `Device Name`, `KEV Count` |
| Top 10 software products by KEV count | Pie chart | `09-Top-Software-by-KEV.kql` | `Software`, `Count` |
| CVE count by device | Table | `10-CVE-Count-by-Device.kql` | Device and severity counts |
| CVEs by severity | Pie chart | `11-CVEs-by-Severity.kql` | `vulnerabilitySeverityLevel`, `CVECount` |
| Top 20 software by CVE count | Table | `12-Top-Software-by-CVE.kql` | Software, vendor, CVE count, and device count |
| All CVE findings with KB enrichment | Table | `13-All-CVE-Findings.kql` | CVE, device, software, severity, CVSS, KB, and exploitability fields |

## Optional Filters

Queries 06 through 09 define empty dynamic arrays at the top. Empty arrays mean **all values**. Add exact values to reproduce workbook filtering, for example:

```kusto
let SelectedDevices = dynamic(["device1.contoso.com"]);
let SelectedCveIds = dynamic(["CVE-2026-0001"]);
```

## Query Design

- CISA comparisons use the CISA feed plus `DeviceTvmSoftwareVulnerabilities` only.
- The small CISA dataset is placed on the left of one broadcast join.
- Only required columns are projected before each join.
- KB enrichment is isolated to query 13, which joins the two native TVM tables without adding the CISA feed.
- The workbook's Time range control has no standalone query because the native TVM tables represent current state rather than time-series events.

Drafting assistance: Claude Opus 4.8 (via GitHub Copilot), grounded in official Microsoft Learn documentation.
