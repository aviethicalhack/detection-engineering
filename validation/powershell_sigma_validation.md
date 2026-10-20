
# PowerShell Sigma Rule Validation

## Rule Under Test

- Rule: Suspicious PowerShell Execution with Encoded or Evasive Arguments
- File: `sigma/windows/proc_suspicious_powershell_v2.yml`
- Data source: Windows process creation telemetry
- Suggested telemetry: Sysmon Event ID 1 or equivalent EDR process-creation events
- Status: Static review and Sigma-to-Splunk conversion completed
- Runtime validation: Pending

## Detection Logic

The rule looks for PowerShell process creation where the command line contains at least one encoded-command indicator or execution-evasion indicator.

## Test Cases

| Test case | Example command-line text | Expected result | Reason |
|---|---|---|---|
| Encoded argument | `powershell.exe -EncodedCommand <placeholder>` | Match | Contains an encoded-command indicator |
| No profile | `powershell.exe -NoProfile` | Match | Contains an evasion indicator |
| Hidden window | `powershell.exe -WindowStyle Hidden` | Match | Contains an evasion indicator |
| Execution policy | `powershell.exe -ExecutionPolicy Bypass` | Match | Contains an evasion indicator |
| Ordinary command | `powershell.exe -File maintenance.ps1` | No match | No listed indicator |
| Other executable | `cmd.exe /c whoami` | No match | Process image is not PowerShell |

These are expected results derived from static rule logic. They have not yet been verified against actual Windows process-creation events or a live SIEM.

## Limitations

- Substring matching can produce false positives.
- Command-line spacing and argument variations may cause missed matches.
- The rule requires process-creation telemetry containing image and command-line fields.
- Legitimate administrative tools may use the same options.
- A successful Sigma conversion does not prove runtime detection accuracy.

## Validation Status

- [x] Sigma rule converted to Splunk SPL
- [x] Detection logic reviewed
- [ ] Rule tested against representative event records
- [ ] False positives assessed
- [ ] Runtime results documented
