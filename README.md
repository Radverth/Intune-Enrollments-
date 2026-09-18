# Intune Autopilot Enrollment Tool

`Invoke-IntuneAutopilotEnroll.ps1` is a single-file, menu-driven PowerShell tool for MSP
technicians who need to register a Windows endpoint into Windows Autopilot / Intune while
standing in front of it.

Authentication is **certificate-based only** — no client secrets are requested, generated,
or written to disk at any point.

## Requirements

| | |
|---|---|
| PowerShell | Windows PowerShell 5.1 or PowerShell 7 (on Windows) |
| Elevation | Required — the tool reads and writes `Cert:\LocalMachine\My` |
| Network | Outbound HTTPS to `graph.microsoft.com` and `www.powershellgallery.com` |
| Tenant rights | Global Administrator (or Privileged Role Administrator) only for the one-time app registration setup |

Missing PowerShell dependencies are installed on demand rather than failing:

- `Microsoft.Graph.Authentication`, `Microsoft.Graph.Applications`,
  `Microsoft.Graph.Identity.SignIns` (modules)
- `Get-WindowsAutopilotInfo` (a PowerShell Gallery **script**, installed with
  `Install-Script`)

## Running it

```powershell
# from an elevated prompt
.\Invoke-IntuneAutopilotEnroll.ps1
```

```
  1. Connect to an existing app registration
  2. Create a new app registration
  3. Enroll this device in Autopilot / Intune
  4. View current configuration
  5. Manage certificates
  6. Exit
```

## Typical workflow

**Once per tenant** — run option **2** on a machine where you can sign in interactively as
a Global Administrator. It creates a self-signed certificate (RSA 2048 / SHA256, 2-year
life) in `Cert:\LocalMachine\My`, creates an app registration whose only credential is that
certificate's public key, creates the service principal, and grants admin consent for the
Graph application permissions below.

If the signed-in account cannot grant consent, the app registration is still created — the
tool prints the manual fallback (*Entra ID > App registrations > your app > API
permissions > Grant admin consent*) rather than crashing.

**On every device thereafter** — run option **3**. It validates the saved config and
certificate, then shells out to `Get-WindowsAutopilotInfo.ps1 -Online` with the tenant, app
ID, and certificate thumbprint, plus any optional Group Tag / Assigned User / Assigned
Computer Name you supply.

Option **1** points the tool at an app registration that already exists. It live-tests the
tenant + app + certificate combination against Graph before saving anything, and explains
the likely cause when the test fails.

### Graph application permissions requested

| Permission | Why |
|---|---|
| `DeviceManagementServiceConfig.ReadWrite.All` | Register devices with the Autopilot service |
| `DeviceManagementManagedDevices.ReadWrite.All` | Read/write Intune managed device records |
| `Device.ReadWrite.All` | Create/update the Entra ID device object |
| `GroupMember.ReadWrite.All` *(optional)* | Group tag / dynamic group flows |

These are resolved **by name** against the Microsoft Graph service principal's `AppRoles` at
runtime rather than from hardcoded GUIDs, so the tool still works in tenants and clouds
where the role IDs differ.

## Deploying to additional endpoints

This is the part worth planning for. Option 3 runs on the **end-user machine being
provisioned**, and app-only certificate auth needs the private key present locally. So each
endpoint you enroll needs two things:

1. `C:\ProgramData\AffinityIT\IntuneAutopilotEnroll\config.json`
2. The certificate, **with its private key**, imported into `Cert:\LocalMachine\My`

The certificate created by option 2 is marked exportable for exactly this reason — export
it once as a `.pfx` and deploy it alongside `config.json` (via RMM, GPO, or by hand), then
every endpoint just runs option 3. Alternatively, import the `.pfx` on the new machine and
run option 1 to re-point the config at it.

Treat the exported `.pfx` as a tenant credential — it grants device-management rights to
whoever holds it.

## Files

| Path | Contents |
|---|---|
| `C:\ProgramData\AffinityIT\IntuneAutopilotEnroll\config.json` | Tenant ID, app ID, app display name, certificate thumbprint. No secrets. |
| `C:\ProgramData\AffinityIT\IntuneAutopilotEnroll\enroll.log` | Timestamped log of every action, including full exception detail. |

`config.json` holds no credential material — the thumbprint is only a pointer to a
certificate in the machine store.

## Certificate management

Option **5** lists every certificate in `Cert:\LocalMachine\My` that has a private key, with
subject, thumbprint and expiry, flagging expired certificates and those the tool created. It
can delete expired certificates, confirming each one individually and warning first if the
certificate is the one the saved configuration depends on.

Certificates expire after two years. Option **4** shows days remaining; when it gets short,
re-run option 2 to create a fresh app registration, or create a new certificate and upload
its public key to the existing app registration and re-run option 1.

## Troubleshooting

Everything lands in `enroll.log`, including the full exception type, category and script
line for any failure — the console only ever shows the readable summary.

| Symptom | Usual cause |
|---|---|
| Connection test fails immediately after option 2 | App role assignments take a minute or two to propagate. Wait, then retry. |
| `AADSTS700027` / invalid client assertion | The certificate public key is not on the app registration. |
| `Authorization_RequestDenied` / 403 | Admin consent was never granted. |
| "Keyset does not exist" | The certificate has no private key, or the running account cannot read it. |
| Device does not appear in Intune | Autopilot device sync takes a few minutes; it is not instant. |
| Script rejects `-CertificateThumbprint` | The installed `Get-WindowsAutopilotInfo` predates certificate auth. `Install-Script -Name Get-WindowsAutopilotInfo -Scope AllUsers -Force` |

## Bulk enrollment via Datto RMM

This tool is single-machine and interactive by design. For bulk enrollment across a site,
see [`DattoRMM/`](DattoRMM/README.md) — a non-interactive component that takes the app
registration details as RMM variables (including the certificate, as base64, since Datto RMM
cannot accept file variables) and calls the Graph API directly with no module dependencies on
the endpoint.

## Out of scope

Any GUI, and automatic dynamic-group creation for group-tag-based profile assignment.
Bulk enrollment is handled by the Datto RMM component described above rather than by this
script.
