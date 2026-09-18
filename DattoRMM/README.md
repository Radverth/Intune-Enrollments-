# Datto RMM — Autopilot Bulk Enrollment

A non-interactive counterpart to the menu-driven `Invoke-IntuneAutopilotEnroll.ps1` in the
repository root, packaged to run as a Datto RMM component against a whole site or device
group.

| | Root tool | This component |
|---|---|---|
| Interaction | Numbered console menu, tech at the keyboard | None — variables only |
| Scope | One device at a time | Bulk, whole site / device group |
| Certificate | Lives in `Cert:\LocalMachine\My` | Base64 string variable, in memory only |
| Dependencies | `Microsoft.Graph.*` + `Get-WindowsAutopilotInfo` | **None** |
| Enrollment call | Shells out to `Get-WindowsAutopilotInfo.ps1` | Calls the Graph REST API directly |

## Why no modules

The root tool installs `Microsoft.Graph.*` and `Get-WindowsAutopilotInfo` on demand, which is
fine for one machine with a technician watching. In a bulk run it is a liability: every
endpoint would need to reach the PowerShell Gallery, bootstrap the NuGet provider, and
complete an `Install-Module`/`Install-Script` as SYSTEM in a non-interactive session. That
turns a dependency install into a per-device failure mode and makes a 200-device job slow and
flaky.

This component instead signs its own OAuth client assertion with the certificate and calls
Graph over `Invoke-RestMethod`. Nothing is installed on the endpoint, and the only outbound
requirements are `login.microsoftonline.com` and `graph.microsoft.com`.

## Setup

### 1. App registration

Create a dedicated app registration for the RMM component with **one** application
permission:

- `DeviceManagementServiceConfig.ReadWrite.All` — covers the import, the already-registered
  pre-check, and the optional device rename.

Grant admin consent. Do not reuse the root tool's broader app registration here if you can
avoid it: that one also holds `Device.ReadWrite.All` and
`DeviceManagementManagedDevices.ReadWrite.All`, and this credential is going to be readable
by everyone with access to your RMM.

You can create the app registration with option 2 of the root tool and then remove the
permissions this component does not need, or create it by hand in Entra ID and upload the
certificate's public key under *Certificates & secrets*.

### 2. Produce the certificate variable

Datto RMM cannot take a file as a variable, so the `.pfx` has to arrive as text. Generate it
with the included helper, on a machine that has the certificate:

```powershell
# Export straight out of the local machine store (elevated)
.\New-AutopilotCertVariable.ps1 -Thumbprint A1B2C3... -Password (Read-Host -AsSecureString)

# ...or from an existing .pfx
.\New-AutopilotCertVariable.ps1 -PfxPath .\autopilot.pfx -Password (Read-Host -AsSecureString)
```

The helper verifies the result before printing it — it decodes the base64 back, loads the
certificate, and performs the same RS256 signing operation the component does against Entra
ID. If that fails it prints nothing usable, because a bad string would fail identically on
every endpoint in the run.

A 2048-bit certificate produces roughly 3,400 characters of base64. If the Datto variable
field rejects a value that long, split it:

```powershell
.\New-AutopilotCertVariable.ps1 -PfxPath .\autopilot.pfx -Password $pw -ChunkSize 2000
```

That emits `AutopilotCertBase64`, `AutopilotCertBase64_2`, and so on, which the component
reassembles in order. **Create every part.** The component stops at the first gap, so a
missing middle part truncates the certificate silently.

### 3. Create the component

- **Category**: Scripts · **Script type**: PowerShell
- Paste `Invoke-AutopilotBulkEnroll.ps1` as the script
- Add the input variables below

The script relaunches itself under 64-bit PowerShell if the agent starts it in a 32-bit
process, because the Autopilot hardware hash lives in a WMI namespace a 32-bit process
cannot reliably read.

## Variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `AutopilotTenantId` | Yes | — | Tenant GUID |
| `AutopilotAppId` | Yes | — | Application (client) GUID |
| `AutopilotCertBase64` | Yes | — | Base64 of the `.pfx`, from the helper |
| `AutopilotCertBase64_2` … `_20` | No | — | Continuation parts, if split |
| `AutopilotCertPassword` | Recommended | — | Password protecting the `.pfx` |
| `AutopilotGroupTag` | No | — | Set per site to drive dynamic-group assignment |
| `AutopilotAssignedUser` | No | — | UPN. Usually blank for bulk |
| `AutopilotAssignedComputerName` | No | — | Supports `%SERIAL%` and `%HOSTNAME%`; capped at 15 chars |
| `AutopilotSkipIfRegistered` | No | `true` | Skip devices already in Autopilot |
| `AutopilotImportTimeoutSeconds` | No | `180` | How long to wait for the import to finish |
| `AutopilotCloud` | No | `Global` | `Global`, `USGov`, `USGovDoD`, `China` |
| `AutopilotUdfNumber` | No | — | 1–30; writes the outcome to that UDF |

Group tags are the main reason to set a variable at **site** level rather than on the
component: the same component can then tag each site's devices differently without being
duplicated.

## Exit codes

Datto treats any non-zero exit as a failed job.

| Code | Meaning | Action |
|---|---|---|
| 0 | Registered, or already registered and skipped | None |
| 1 | Configuration error | Fix the variables; the output names each problem |
| 2 | Certificate could not be loaded | Wrong password, truncated base64, or no private key |
| 3 | Authentication failed | Certificate not on the app registration, or consent missing |
| 4 | No serial number or hardware hash | Often a VM, or a placeholder BIOS serial |
| 5 | Graph rejected the import | See the error name in the output |
| 6 | Partial — submitted or registered, but unconfirmed / not renamed | Verify in Intune before re-running |
| 7 | Unexpected error | Check `bulk-enroll.log` on the device |

Code 6 is deliberately non-zero. The device is very likely fine, but the job should not
claim success it did not confirm.

## Output

Per-device results land in three places:

- **Activity log** (stdout) — a timestamped line per step, with hints on failures.
- **Result field** — `AutopilotStatus`, `AutopilotSerial`, `AutopilotGroupTag`,
  `AutopilotComputerName`, `AutopilotMessage`, so the job list can be sorted and filtered
  without opening each device.
- **`C:\ProgramData\AffinityIT\IntuneAutopilotEnroll\bulk-enroll.log`** on the endpoint.

Set `AutopilotUdfNumber` to also stamp the outcome onto a UDF, which makes "show me every
device that has not enrolled" a device-list filter instead of a job-by-job review.

`AutopilotStatus` values: `Registered`, `AlreadyRegistered`, `SubmittedUnconfirmed`,
`RegisteredNameNotSet`, `ConfigError`, `CertError`, `AuthError`, `HardwareError`,
`ImportFailed`, `UnexpectedError`.

## Security

Be clear-eyed about the trade-off this design makes.

Putting a `.pfx` into an RMM variable means **anyone who can read that variable holds a
credential that can register and modify devices in your tenant.** That includes your RMM
operators, and potentially anyone who can read job output or an RMM audit trail. Datto RMM
has no file-variable mechanism, so there is no version of this that avoids the exposure — it
can only be contained:

- **Use a dedicated app registration** with only `DeviceManagementServiceConfig.ReadWrite.All`.
  Do not reuse a broader one.
- **Always set a password** on the `.pfx` and store it in a separate variable, so one leaked
  value is not immediately usable.
- **Mask the variables** if your Datto RMM tier supports masked site/account variables.
- **Use a short-lived certificate** and rotate it after a bulk campaign finishes. Rotation is
  re-running the helper and updating the variable.
- **Remove the variables** when the campaign is done.

What the component itself does to limit exposure: the certificate is never imported into the
certificate store and never written to disk. It is decoded in memory, used, and explicitly
disposed in a `finally` block, so the private key is not left behind on the hundreds of
endpoints the job touched. This matters — the alternative would leave a tenant-wide
device-management credential readable by any local administrator on every enrolled machine.

An alternative worth considering if the exposure is unacceptable: host the `.pfx` on an
authenticated internal endpoint and fetch it at runtime. That trades an RMM-readable secret
for a network dependency and a different credential to manage, so it is not obviously better
— but it does keep the key out of the RMM database.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Exit 1, "is not a GUID" | A variable has a display name or URL pasted into it |
| Exit 2, "not valid base64" | Truncated value, or a missing continuation part |
| Exit 2, "no private key" | A `.cer`/`.crt` was encoded instead of a `.pfx` |
| Exit 3, `AADSTS700027` | The certificate's public key is not on the app registration — compare thumbprints |
| Exit 3, `AADSTS90002` | Wrong tenant ID |
| Exit 4 on VMs | Many hypervisors cannot produce an Autopilot hardware hash |
| Exit 4, placeholder serial | Whitebox hardware reporting `Default string` etc.; Autopilot keys off the serial |
| Exit 5, `ZtdDeviceAlreadyAssigned` | Registered to another tenant; deregister there first |
| Exit 5, HTTP 403 | Missing permission or admin consent |
| Every device fails identically | Almost always the certificate variable — re-run the helper, which verifies it |

Throttling is handled automatically: HTTP 429 and 5xx are retried with backoff, honouring the
service's `Retry-After` when it sends one. A bulk run across a large site is expected to hit
this.

## Verification status

The following are covered by tests run against this code: the base64 → certificate → RS256
client assertion path (including verifying the produced JWT's signature against the
certificate's public key, which is the same check Entra ID performs), variable parsing
including Datto's blank-value placeholders, multi-part certificate reassembly, `Retry-After`
handling on both the Windows PowerShell and PowerShell 7 header shapes, name-token expansion,
hardware validation, and the result-block formatting.

**Not verified**, because it needs Windows and a real tenant: the WMI hardware-hash retrieval,
the live Graph import/poll/rename calls, the 32-bit relaunch, UDF writes, and Datto's own
variable and result-field plumbing. Run it against one pilot device before pointing it at a
site.
