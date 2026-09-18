#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    One-time setup for the Datto RMM bulk enrollment component: creates the app registration,
    certificate and Datto variable values, and writes them all to a text file.

.DESCRIPTION
    Run this once per tenant, on an admin workstation, signed in as someone who can grant
    admin consent. It:

      1. creates a self-signed certificate (RSA 2048 / SHA256 / 2-year) in Cert:\LocalMachine\My
      2. creates an app registration whose only credential is that certificate -- no secrets
      3. requests the single Graph application permission the bulk component needs, resolved
         by name rather than by hardcoded GUID
      4. creates the service principal and grants admin consent
      5. PROVES the result works by acquiring an app-only token and making a real Autopilot
         read with it, retrying while the assignment propagates
      6. exports the certificate as a password-protected .pfx, base64-encodes it, and writes
         every value -- including the ready-to-paste Datto RMM variables -- to a text file

    Step 5 is the point of doing this as one script. A token proves the certificate is
    accepted; only a real Graph call proves the app role assignment actually landed. Finding
    that out here beats finding out from 200 failed RMM jobs.

.PARAMETER DisplayName
    App registration display name.

.PARAMETER OutFile
    Where to write the results. Defaults to a timestamped file in the current directory.

.PARAMETER CertPassword
    Password for the exported .pfx. A strong one is generated if you do not supply it.

.PARAMETER ChunkSize
    Split the base64 certificate across numbered variables of at most this many characters,
    for Datto RMM variable fields that reject long values. 0 (default) emits one value.

.PARAMETER AdditionalPermission
    Extra Graph application permissions to request by name. The default set is deliberately
    minimal; only add to it if you know you need to.

.PARAMETER RemoveCertificateFromStore
    Delete the certificate from Cert:\LocalMachine\My once it has been exported. The
    certificate's home for this workflow is the Datto variable, not this machine -- but you
    then cannot re-export it, so keep the output file safe.

.EXAMPLE
    .\New-AutopilotBulkAppRegistration.ps1

.EXAMPLE
    .\New-AutopilotBulkAppRegistration.ps1 -ChunkSize 2000 -OutFile C:\Temp\autopilot-setup.txt
#>

[CmdletBinding()]
param(
    [string]$DisplayName = 'AffinityIT Autopilot Bulk Enrollment (Datto RMM)',

    [string]$OutFile,

    [System.Security.SecureString]$CertPassword,

    [ValidateRange(0, 100000)]
    [int]$ChunkSize = 0,

    [string[]]$AdditionalPermission = @(),

    [switch]$RemoveCertificateFromStore,

    # --- Verification-only mode -------------------------------------------------
    # Re-checks an app registration this script already created, without creating
    # anything. Use it after granting admin consent by hand, to confirm the setup works
    # before pointing the component at a site.
    [switch]$VerifyOnly,

    [string]$TenantId,

    [string]$AppId,

    [string]$Thumbprint
)

$ErrorActionPreference = 'Stop'

#region --------------------------------------------------------------- Constants

$Script:GraphAppId       = '00000003-0000-0000-c000-000000000000'
$Script:CertStore        = 'Cert:\LocalMachine\My'
$Script:CertFriendlyName = 'AffinityIT Autopilot Bulk Enroll (Datto RMM)'

# The bulk component does exactly three things against Graph -- import a device, check
# whether a serial is already registered, and optionally set a device name -- and this one
# application permission covers all three. Keeping it to one permission matters here because
# this credential ends up readable by everyone with access to the RMM.
$Script:RequiredPermissions = @(
    [pscustomobject]@{
        Name    = 'DeviceManagementServiceConfig.ReadWrite.All'
        Purpose = 'Import devices into Autopilot, read existing registrations, set device names'
    }
)

$Script:GraphScopes = @(
    'Application.ReadWrite.All'
    'AppRoleAssignment.ReadWrite.All'
    'Directory.Read.All'
)

$Script:Transcript = [System.Collections.Generic.List[string]]::new()

#endregion

#region --------------------------------------------------------------- Output helpers

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ''
    Write-Host "==> $Message" -ForegroundColor Cyan
    $Script:Transcript.Add("==> $Message")
}

function Write-Ok {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "    $Message" -ForegroundColor Green
    $Script:Transcript.Add("    OK   $Message")
}

function Write-Note {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "    $Message" -ForegroundColor Gray
    $Script:Transcript.Add("    ..   $Message")
}

function Write-Warn {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "    $Message" -ForegroundColor Yellow
    $Script:Transcript.Add("    WARN $Message")
}

function Write-Bad {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "    $Message" -ForegroundColor Red
    $Script:Transcript.Add("    FAIL $Message")
}

#endregion

#region --------------------------------------------------------------- Utilities

function New-StrongPassword {
    <#
        Cryptographically random, and drawn from a charset with the visually ambiguous
        characters removed -- this password gets copied out of a text file by hand.
    #>
    [CmdletBinding()]
    param([int]$Length = 28)

    $charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_'
    $bytes   = New-Object byte[] $Length

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try   { $rng.GetBytes($bytes) }
    finally { $rng.Dispose() }

    $chars = foreach ($b in $bytes) { $charset[$b % $charset.Length] }
    return -join $chars
}

function ConvertFrom-SecureStringPlain {
    [CmdletBinding()]
    param([System.Security.SecureString]$Secure)

    if (-not $Secure) { return '' }

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try   { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Split-Base64ForVariables {
    <#
        Produces the Datto variable name/value pairs, splitting across numbered continuation
        variables when a chunk size is given. Matches what the bulk component reassembles.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Base64,
        [int]$ChunkSize = 0
    )

    if ($ChunkSize -le 0 -or $Base64.Length -le $ChunkSize) {
        return @([pscustomobject]@{ Name = 'AutopilotCertBase64'; Value = $Base64 })
    }

    $parts = [Math]::Ceiling($Base64.Length / $ChunkSize)
    $out   = @()

    for ($i = 0; $i -lt $parts; $i++) {
        $start  = $i * $ChunkSize
        $length = [Math]::Min($ChunkSize, $Base64.Length - $start)
        $out += [pscustomobject]@{
            Name  = if ($i -eq 0) { 'AutopilotCertBase64' } else { "AutopilotCertBase64_$($i + 1)" }
            Value = $Base64.Substring($start, $length)
        }
    }

    return $out
}

function Install-GraphModule {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    if (Get-Module -Name $Name) { return $true }

    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Note "Installing module '$Name' from the PowerShell Gallery..."
        try {
            if ([Net.ServicePointManager]::SecurityProtocol -notmatch 'Tls12') {
                [Net.ServicePointManager]::SecurityProtocol =
                    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            }
            $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
            if (-not $nuget -or $nuget.Version -lt [version]'2.8.5.201') {
                $null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers
            }
            Install-Module -Name $Name -Scope AllUsers -Force -AllowClobber -Repository PSGallery
            Write-Ok "Installed '$Name'."
        }
        catch {
            Write-Bad "Could not install '$Name': $($_.Exception.Message)"
            Write-Note "Install it manually: Install-Module $Name -Scope AllUsers"
            return $false
        }
    }

    try {
        Import-Module -Name $Name -ErrorAction Stop
        return $true
    }
    catch {
        Write-Bad "Could not import '$Name': $($_.Exception.Message)"
        return $false
    }
}

#endregion

#region --------------------------------------------------------------- App-only verification

<#
    The client-assertion and token code below is duplicated from
    Invoke-AutopilotBulkEnroll.ps1 on purpose. That component has to be a single self-
    contained file because it is pasted into the Datto RMM component editor, so it cannot
    dot-source a shared helper. Verifying with the same code the component runs is worth more
    here than avoiding the duplication -- please do not "fix" this by making the component
    depend on an external file.
#>

function ConvertTo-Base64Url {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)
    return ([Convert]::ToBase64String($Bytes).TrimEnd('=') -replace '\+', '-' -replace '/', '_')
}

function New-ClientAssertion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Certificate,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId
    )

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if (-not $rsa) { throw 'The certificate private key could not be opened for signing.' }

    $now = [DateTimeOffset]::UtcNow

    $header = [ordered]@{
        alg = 'RS256'
        typ = 'JWT'
        x5t = (ConvertTo-Base64Url -Bytes $Certificate.GetCertHash())
    }
    $payload = [ordered]@{
        aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        iss = $ClientId
        sub = $ClientId
        jti = [guid]::NewGuid().ToString()
        nbf = [int64]$now.AddMinutes(-5).ToUnixTimeSeconds()
        exp = [int64]$now.AddMinutes(10).ToUnixTimeSeconds()
    }

    $enc      = [System.Text.Encoding]::UTF8
    $unsigned = '{0}.{1}' -f (ConvertTo-Base64Url -Bytes $enc.GetBytes(($header  | ConvertTo-Json -Compress))),
                             (ConvertTo-Base64Url -Bytes $enc.GetBytes(($payload | ConvertTo-Json -Compress)))

    $signature = $rsa.SignData(
        $enc.GetBytes($unsigned),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )

    return "$unsigned.$(ConvertTo-Base64Url -Bytes $signature)"
}

function Test-AppOnlyAccess {
    <#
        Acquires an app-only token with the certificate and then makes a real Autopilot read.

        Both halves matter. A token only proves Entra ID accepts the certificate; it says
        nothing about whether the app role assignment landed. The Graph call is what proves
        the permission works. Newly granted assignments take a little while to propagate, so
        this retries rather than failing on the first 403.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Certificate,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [int]$TimeoutSeconds = 240
    )

    $result = [pscustomobject]@{
        TokenAcquired = $false
        GraphReadOk   = $false
        Message       = ''
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $attempt  = 0

    while ((Get-Date) -lt $deadline) {
        $attempt++

        # --- token ---
        $token = $null
        try {
            $assertion = New-ClientAssertion -Certificate $Certificate -TenantId $TenantId -ClientId $ClientId
            $response  = Invoke-RestMethod -Method Post `
                                           -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                                           -Body @{
                                               client_id             = $ClientId
                                               client_assertion      = $assertion
                                               client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                                               scope                 = 'https://graph.microsoft.com/.default'
                                               grant_type            = 'client_credentials'
                                           } `
                                           -ContentType 'application/x-www-form-urlencoded'
            $token = $response.access_token
            if (-not $result.TokenAcquired) {
                $result.TokenAcquired = $true
                Write-Ok 'App-only token acquired with the certificate.'
            }
        }
        catch {
            $detail = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $_.Exception.Message }
            $result.Message = ($detail -replace '\s+', ' ')
            Write-Note "Token attempt $attempt failed, retrying while the app registration propagates..."
            Start-Sleep -Seconds 15
            continue
        }

        # --- real Graph read, which is what actually tests the permission ---
        try {
            $null = Invoke-RestMethod -Method Get `
                                      -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$top=1' `
                                      -Headers @{ Authorization = "Bearer $token" }

            $result.GraphReadOk = $true
            $result.Message     = 'Token acquired and Autopilot read succeeded.'
            Write-Ok 'Autopilot read succeeded -- the permission is live and consented.'
            return $result
        }
        catch {
            $detail = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $_.Exception.Message }
            $result.Message = ($detail -replace '\s+', ' ')

            $status = 0
            try { $status = [int]$_.Exception.Response.StatusCode } catch { $status = 0 }

            if ($status -eq 403 -or $status -eq 401) {
                Write-Note "Graph returned $status (attempt $attempt) -- the app role assignment has not propagated yet, waiting..."
                Start-Sleep -Seconds 15
                continue
            }

            Write-Bad "Graph read failed with an unexpected error: $($result.Message)"
            return $result
        }
    }

    return $result
}

#endregion

#region --------------------------------------------------------------- Report

function Write-SetupReport {
    <#
        Writes everything the technician needs into one file: the identifiers, the permission
        outcome, and the Datto RMM variables as literal Name=Value lines ready to be copied
        into the component.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Setup,
        [Parameter(Mandatory)][string]$Path
    )

    $nl    = [Environment]::NewLine
    $rule  = '=' * 78
    $thin  = '-' * 78
    $lines = [System.Collections.Generic.List[string]]::new()

    function Add-Line { param([string]$Text = '') $lines.Add($Text) }

    Add-Line $rule
    Add-Line '  AUTOPILOT BULK ENROLLMENT - DATTO RMM SETUP RESULTS'
    Add-Line $rule
    Add-Line ''
    Add-Line ('  Generated    : {0}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))
    Add-Line ('  Generated by : {0}\{1} on {2}' -f $env:USERDOMAIN, $env:USERNAME, $env:COMPUTERNAME)
    Add-Line ('  Signed in as : {0}' -f $Setup.SignedInAs)
    Add-Line ''
    Add-Line '  !! THIS FILE CONTAINS A PRIVATE KEY !!'
    Add-Line ''
    Add-Line '  The certificate below is a credential that can register and modify devices'
    Add-Line '  in your tenant. Once the Datto RMM variables are created, delete this file'
    Add-Line '  or move it into your password manager / documentation vault. Do not leave it'
    Add-Line '  on a shared drive or in a ticket attachment.'
    Add-Line ''

    Add-Line $rule
    Add-Line '  1. TENANT AND APP REGISTRATION'
    Add-Line $rule
    Add-Line ''
    Add-Line ('  Tenant ID            : {0}' -f $Setup.TenantId)
    Add-Line ('  Tenant name          : {0}' -f $Setup.TenantName)
    Add-Line ('  App display name     : {0}' -f $Setup.DisplayName)
    Add-Line ('  App (client) ID      : {0}' -f $Setup.AppId)
    Add-Line ('  App object ID        : {0}' -f $Setup.AppObjectId)
    Add-Line ('  Service principal ID : {0}' -f $Setup.ServicePrincipalId)
    Add-Line ''

    Add-Line $rule
    Add-Line '  2. GRAPH APPLICATION PERMISSIONS'
    Add-Line $rule
    Add-Line ''
    foreach ($permission in $Setup.Permissions) {
        Add-Line ('  [{0}] {1}' -f $permission.State, $permission.Name)
        Add-Line ('        {0}' -f $permission.Purpose)
    }
    Add-Line ''
    if ($Setup.ConsentFailed.Count -gt 0) {
        Add-Line '  ** ADMIN CONSENT WAS NOT GRANTED AUTOMATICALLY **'
        Add-Line ''
        Add-Line '  The app registration exists, but these permissions still need consent:'
        foreach ($name in $Setup.ConsentFailed) { Add-Line ("      - {0}" -f $name) }
        Add-Line ''
        Add-Line '  Grant it in the portal, as a Global Administrator:'
        Add-Line ('      Entra ID > App registrations > {0} > API permissions' -f $Setup.DisplayName)
        Add-Line '      then "Grant admin consent for <tenant>".'
        Add-Line ''
        Add-Line '  The bulk component will fail with exit code 3 on every device until this'
        Add-Line '  is done.'
        Add-Line ''
    }

    Add-Line $rule
    Add-Line '  3. CERTIFICATE'
    Add-Line $rule
    Add-Line ''
    Add-Line ('  Thumbprint  : {0}' -f $Setup.CertThumbprint)
    Add-Line ('  Subject     : {0}' -f $Setup.CertSubject)
    Add-Line ('  Valid from  : {0}' -f $Setup.CertNotBefore)
    Add-Line ('  Expires     : {0}   <-- the bulk component stops working on this date' -f $Setup.CertNotAfter)
    Add-Line ('  In store    : {0}' -f $Setup.CertInStore)
    Add-Line ''
    Add-Line ('  PFX password: {0}' -f $Setup.CertPassword)
    Add-Line ''

    Add-Line $rule
    Add-Line '  4. VERIFICATION'
    Add-Line $rule
    Add-Line ''
    Add-Line ('  App-only token acquired : {0}' -f $(if ($Setup.Verification.TokenAcquired) { 'YES' } else { 'NO' }))
    Add-Line ('  Live Autopilot read     : {0}' -f $(if ($Setup.Verification.GraphReadOk)   { 'YES' } else { 'NO' }))
    if (-not $Setup.Verification.GraphReadOk) {
        Add-Line ''
        Add-Line ('  Last error: {0}' -f $Setup.Verification.Message)
        Add-Line ''
        Add-Line '  Do not roll this out to a site until the live read succeeds. Re-run the'
        Add-Line '  verification at any time with:'
        Add-Line ''
        Add-Line ('      .\New-AutopilotBulkAppRegistration.ps1 -VerifyOnly `' )
        Add-Line ('          -TenantId {0} `' -f $Setup.TenantId)
        Add-Line ('          -AppId {0} `' -f $Setup.AppId)
        Add-Line ('          -Thumbprint {0}' -f $Setup.CertThumbprint)
        Add-Line ''
        Add-Line '  That re-runs the check only. It creates nothing.'
    }
    Add-Line ''

    Add-Line $rule
    Add-Line '  5. DATTO RMM COMPONENT VARIABLES'
    Add-Line $rule
    Add-Line ''
    Add-Line '  Create these as input variables on the component (or at site/account level).'
    Add-Line '  Copy each value exactly -- no leading or trailing spaces, no line breaks.'
    Add-Line ''
    Add-Line $thin
    Add-Line ''
    Add-Line ('AutopilotTenantId={0}' -f $Setup.TenantId)
    Add-Line ''
    Add-Line ('AutopilotAppId={0}' -f $Setup.AppId)
    Add-Line ''
    Add-Line ('AutopilotCertPassword={0}' -f $Setup.CertPassword)
    Add-Line ''

    foreach ($part in $Setup.CertVariables) {
        Add-Line ('{0}={1}' -f $part.Name, $part.Value)
        Add-Line ''
    }

    Add-Line $thin
    Add-Line ''

    if ($Setup.CertVariables.Count -gt 1) {
        Add-Line ('  The certificate is split across {0} variables because a chunk size was' -f $Setup.CertVariables.Count)
        Add-Line '  requested. CREATE ALL OF THEM, in order. The component stops reassembling at'
        Add-Line '  the first gap, so a missing middle part truncates the certificate silently.'
        Add-Line ''
    }
    else {
        Add-Line ('  AutopilotCertBase64 is {0} characters. If the Datto variable field rejects' -f $Setup.CertVariables[0].Value.Length)
        Add-Line '  a value that long, re-run this script with -ChunkSize 2000 to split it.'
        Add-Line ''
    }

    Add-Line '  Optional variables (see DattoRMM/README.md for the full list):'
    Add-Line ''
    Add-Line '      AutopilotGroupTag               set per SITE to tag each client differently'
    Add-Line '      AutopilotAssignedComputerName   supports %SERIAL% and %HOSTNAME%'
    Add-Line '      AutopilotUdfNumber              1-30, stamps the outcome onto a UDF'
    Add-Line '      AutopilotSkipIfRegistered       default true'
    Add-Line '      AutopilotCloud                  Global (default), USGov, USGovDoD, China'
    Add-Line ''

    Add-Line $rule
    Add-Line '  6. NEXT STEPS'
    Add-Line $rule
    Add-Line ''
    Add-Line '  1. Create the Datto RMM component (Scripts / PowerShell) from'
    Add-Line '     DattoRMM\Invoke-AutopilotBulkEnroll.ps1'
    Add-Line '  2. Add the variables from section 5.'
    Add-Line '  3. Run it against ONE pilot device first and confirm exit code 0.'
    Add-Line '  4. Then schedule or run it against the site.'
    Add-Line '  5. Delete this file, or store it somewhere appropriate for a private key.'
    Add-Line ''
    Add-Line ('  Diarise the certificate expiry: {0}' -f $Setup.CertNotAfter)
    Add-Line '  Rotating it means re-running this script and updating the variables.'
    Add-Line ''

    Add-Line $rule
    Add-Line '  RUN LOG'
    Add-Line $rule
    Add-Line ''
    foreach ($entry in $Setup.Transcript) { Add-Line $entry }
    Add-Line ''

    $content = ($lines -join $nl)

    # Restrict the file to Administrators and SYSTEM before the secret goes into it, so it is
    # never briefly readable by everyone on a machine with a permissive directory ACL.
    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -Path $directory -ItemType Directory -Force
    }

    Set-Content -LiteralPath $Path -Value $content -Encoding UTF8

    try {
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)   # drop inheritance
        foreach ($identity in @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM')) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $identity, 'FullControl', 'Allow')))
        }
        Set-Acl -LiteralPath $Path -AclObject $acl
        Write-Ok 'Output file restricted to Administrators and SYSTEM.'
    }
    catch {
        Write-Warn "Could not tighten the ACL on the output file: $($_.Exception.Message)"
        Write-Warn 'Check its permissions manually -- it contains a private key.'
    }

    return $Path
}

#endregion

#region --------------------------------------------------------------- Verify-only mode

function Invoke-VerifyOnly {
    <#
        Runs only the verification half against an app registration that already exists.

        This is the path back after consent was granted manually: the app registration and
        certificate are already in place, and all that is unknown is whether the permission
        has actually landed. Re-running the full setup would create a second app registration,
        which is not what anyone wants.
    #>
    [CmdletBinding()]
    param()

    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host '  Autopilot Bulk Enrollment - verification only' -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan

    $missing = @()
    if ([string]::IsNullOrWhiteSpace($TenantId))   { $missing += '-TenantId' }
    if ([string]::IsNullOrWhiteSpace($AppId))      { $missing += '-AppId' }
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) { $missing += '-Thumbprint' }
    if ($missing.Count -gt 0) {
        throw ("-VerifyOnly also needs: {0}. They are all in section 1 and 3 of the setup results file." -f ($missing -join ', '))
    }

    $clean = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($clean -notmatch '^[0-9A-F]{40}$') { throw "'$Thumbprint' is not a 40-character hex thumbprint." }

    Write-Step 'Locating the certificate'
    $certPath = Join-Path $Script:CertStore $clean
    if (-not (Test-Path -LiteralPath $certPath)) {
        throw "No certificate with thumbprint $clean is in $Script:CertStore on this machine. Run this on the machine where the setup script created it."
    }

    $certificate = Get-Item -LiteralPath $certPath
    if (-not $certificate.HasPrivateKey) { throw 'That certificate has no private key, so it cannot authenticate.' }
    Write-Ok "Found $($certificate.Thumbprint), expires $($certificate.NotAfter.ToString('yyyy-MM-dd'))."

    if ($certificate.NotAfter -lt (Get-Date)) {
        Write-Bad 'The certificate has EXPIRED. Create a new one -- verification cannot succeed.'
        return 1
    }

    Write-Step 'Verifying app-only access'
    $verification = Test-AppOnlyAccess -Certificate $certificate -TenantId $TenantId -ClientId $AppId

    Write-Host ''
    if ($verification.GraphReadOk) {
        Write-Host '  VERIFIED: app-only token acquired and a live Autopilot read succeeded.' -ForegroundColor Green
        Write-Host '  The bulk component is safe to roll out with these values.' -ForegroundColor Green
        Write-Host ''
        return 0
    }

    if ($verification.TokenAcquired) {
        Write-Host '  PARTIAL: the certificate authenticates, but the Autopilot read failed.' -ForegroundColor Yellow
        Write-Host '  That points at the permission, not the certificate -- confirm admin consent' -ForegroundColor Yellow
        Write-Host '  for DeviceManagementServiceConfig.ReadWrite.All has been granted.' -ForegroundColor Yellow
    }
    else {
        Write-Host '  FAILED: no app-only token could be acquired.' -ForegroundColor Red
        Write-Host '  That points at the certificate or the IDs, not the permission.' -ForegroundColor Red
    }

    Write-Host ''
    Write-Host "  Last error: $($verification.Message)" -ForegroundColor DarkGray
    Write-Host ''
    return 1
}

#endregion

#region --------------------------------------------------------------- Main

function Invoke-Setup {
    [CmdletBinding()]
    param()

    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host '  Autopilot Bulk Enrollment - Datto RMM setup' -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host ''
    Write-Host '  Creates the app registration, certificate and Datto variable values for the'
    Write-Host '  bulk enrollment component, then writes them to a text file.'
    Write-Host ''
    Write-Host '  You need to sign in as a Global Administrator (or Privileged Role'
    Write-Host '  Administrator) of the target tenant.'
    Write-Host ''

    # ---- Resolve output path and password early, so we fail before creating anything ----
    if ([string]::IsNullOrWhiteSpace($OutFile)) {
        $stamp   = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $OutFile = Join-Path (Get-Location).Path "AutopilotBulkEnroll-Setup-$stamp.txt"
    }
    $OutFile = [IO.Path]::GetFullPath($OutFile)

    $plainPassword = ConvertFrom-SecureStringPlain -Secure $CertPassword
    $generated     = $false
    if ([string]::IsNullOrEmpty($plainPassword)) {
        $plainPassword = New-StrongPassword
        $generated     = $true
    }

    Write-Note "Results will be written to: $OutFile"
    if ($generated) { Write-Note 'A strong .pfx password was generated and will be in the output file.' }

    # ---- Modules ----
    Write-Step 'Checking prerequisites'
    foreach ($module in @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Applications')) {
        if (-not (Install-GraphModule -Name $module)) {
            throw "Required module '$module' is unavailable."
        }
    }
    Write-Ok 'Graph modules ready.'

    # ---- Sign in ----
    Write-Step 'Signing in to Microsoft Graph'
    try { $null = Disconnect-MgGraph -ErrorAction SilentlyContinue } catch { }

    Connect-MgGraph -Scopes $Script:GraphScopes -NoWelcome -ErrorAction Stop | Out-Null
    $context = Get-MgContext -ErrorAction Stop
    $tenantId = $context.TenantId
    Write-Ok "Signed in as $($context.Account) (tenant $tenantId)."

    $tenantName = ''
    try {
        $org = Invoke-MgGraphRequest -Method GET -Uri 'v1.0/organization?$select=displayName'
        $tenantName = @($org.value)[0].displayName
        Write-Note "Tenant: $tenantName"
    }
    catch {
        Write-Note 'Could not read the tenant display name (not required).'
    }

    # ---- Resolve permissions by name ----
    Write-Step 'Resolving Graph application permissions'
    $wanted = @($Script:RequiredPermissions)
    foreach ($extra in $AdditionalPermission) {
        if ([string]::IsNullOrWhiteSpace($extra)) { continue }
        if ($wanted.Name -contains $extra) { continue }
        $wanted += [pscustomobject]@{ Name = $extra; Purpose = 'Requested with -AdditionalPermission' }
        Write-Note "Additional permission requested: $extra"
    }

    $graphSp = Get-MgServicePrincipal -Filter "appId eq '$Script:GraphAppId'" -ErrorAction Stop | Select-Object -First 1
    if (-not $graphSp) { throw "The Microsoft Graph service principal ($Script:GraphAppId) was not found in this tenant." }

    $resolved = @()
    foreach ($permission in $wanted) {
        $role = $graphSp.AppRoles |
                    Where-Object { $_.Value -eq $permission.Name -and $_.AllowedMemberTypes -contains 'Application' } |
                    Select-Object -First 1

        if (-not $role) {
            throw "The permission '$($permission.Name)' could not be resolved against the Graph service principal in this tenant."
        }

        $resolved += [pscustomobject]@{
            Name    = $permission.Name
            Purpose = $permission.Purpose
            Id      = $role.Id
        }
        Write-Ok "$($permission.Name) -> $($role.Id)"
    }

    # ---- Certificate ----
    Write-Step 'Creating the certificate'
    $certSubject = "$DisplayName ($env:COMPUTERNAME)"
    $certificate = New-SelfSignedCertificate -Subject "CN=$certSubject" `
                                             -CertStoreLocation $Script:CertStore `
                                             -KeyAlgorithm RSA `
                                             -KeyLength 2048 `
                                             -HashAlgorithm SHA256 `
                                             -KeyExportPolicy Exportable `
                                             -KeySpec Signature `
                                             -KeyUsage DigitalSignature `
                                             -NotBefore (Get-Date).AddMinutes(-10) `
                                             -NotAfter (Get-Date).AddYears(2) `
                                             -FriendlyName $Script:CertFriendlyName `
                                             -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider' `
                                             -ErrorAction Stop

    Write-Ok "Created $($certificate.Thumbprint), expires $($certificate.NotAfter.ToString('yyyy-MM-dd'))."

    # ---- App registration ----
    Write-Step 'Creating the app registration'
    $app = New-MgApplication -DisplayName $DisplayName `
                             -SignInAudience 'AzureADMyOrg' `
                             -KeyCredentials @(@{
                                 Type          = 'AsymmetricX509Cert'
                                 Usage         = 'Verify'
                                 Key           = $certificate.RawData
                                 DisplayName   = "CN=$certSubject"
                                 StartDateTime = $certificate.NotBefore
                                 EndDateTime   = $certificate.NotAfter
                             }) `
                             -RequiredResourceAccess @(@{
                                 ResourceAppId  = $Script:GraphAppId
                                 ResourceAccess = @($resolved | ForEach-Object { @{ Id = $_.Id; Type = 'Role' } })
                             }) `
                             -Notes 'Created by New-AutopilotBulkAppRegistration.ps1 for the Datto RMM bulk enrollment component. Certificate auth only.' `
                             -ErrorAction Stop

    Write-Ok "Created '$DisplayName' (AppId $($app.AppId))."

    # ---- Service principal ----
    Write-Step 'Creating the service principal'
    $clientSp = $null
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try {
            $clientSp = New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop
            break
        }
        catch {
            if ($_.Exception.Message -match 'already exists|Another object with the same value') {
                $clientSp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($clientSp) { break }
            }
            if ($attempt -eq 6) { throw }
            Write-Note "Not ready yet (attempt $attempt/6) -- waiting for directory replication..."
            Start-Sleep -Seconds 5
        }
    }
    if (-not $clientSp) { throw 'The service principal could not be created.' }
    Write-Ok "Created service principal $($clientSp.Id)."

    # ---- Admin consent ----
    Write-Step 'Granting admin consent'
    $consentFailed = @()
    $permissionReport = @()

    foreach ($role in $resolved) {
        $state = 'GRANTED'
        try {
            $null = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $clientSp.Id `
                                                            -BodyParameter @{
                                                                principalId = $clientSp.Id
                                                                resourceId  = $graphSp.Id
                                                                appRoleId   = $role.Id
                                                            } `
                                                            -ErrorAction Stop
            Write-Ok "Consented: $($role.Name)"
        }
        catch {
            if ($_.Exception.Message -match 'already exists|already assigned') {
                Write-Ok "Already consented: $($role.Name)"
            }
            else {
                $state = 'NOT CONSENTED'
                $consentFailed += $role.Name
                Write-Bad "Could not consent $($role.Name): $($_.Exception.Message)"
            }
        }

        $permissionReport += [pscustomobject]@{
            Name    = $role.Name
            Purpose = $role.Purpose
            State   = $state
        }
    }

    if ($consentFailed.Count -gt 0) {
        Write-Warn 'Admin consent could not be granted automatically. This usually means the'
        Write-Warn 'signed-in account is not a Global Administrator or Privileged Role Administrator.'
        Write-Warn "Grant it manually: Entra ID > App registrations > $DisplayName > API permissions."
    }

    # ---- Verify it actually works ----
    Write-Step 'Verifying app-only access (this is the step that catches consent problems)'
    $verification = if ($consentFailed.Count -gt 0) {
        Write-Warn 'Skipping verification because consent is outstanding -- it would only fail.'
        [pscustomobject]@{ TokenAcquired = $false; GraphReadOk = $false; Message = 'Skipped: admin consent outstanding.' }
    }
    else {
        Test-AppOnlyAccess -Certificate $certificate -TenantId $tenantId -ClientId $app.AppId
    }

    if (-not $verification.GraphReadOk -and $consentFailed.Count -eq 0) {
        Write-Warn 'Verification did not succeed. The output file records this -- do not roll out'
        Write-Warn 'to a site until it does.'
    }

    # ---- Export and encode ----
    Write-Step 'Exporting the certificate for the Datto variable'
    $pfxBytes = $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $plainPassword)
    $base64   = [Convert]::ToBase64String($pfxBytes)
    Write-Ok "Exported $($pfxBytes.Length) bytes; base64 is $($base64.Length) characters."

    # Prove the encoded copy round-trips and can sign, rather than trusting it.
    $check = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(
        [Convert]::FromBase64String($base64),
        $plainPassword,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
    )
    try {
        if (-not $check.HasPrivateKey) { throw 'the round-tripped certificate has no private key' }
        $rsa   = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($check)
        $probe = [Text.Encoding]::UTF8.GetBytes('autopilot-client-assertion-probe')
        $sig   = $rsa.SignData($probe, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        if (-not $rsa.VerifyData($probe, $sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)) {
            throw 'the RS256 signature did not verify'
        }
        Write-Ok 'Encoded certificate verified: decodes, has its private key, and signs correctly.'
    }
    finally {
        $check.Dispose()
    }

    $certVariables = @(Split-Base64ForVariables -Base64 $base64 -ChunkSize $ChunkSize)
    if ($certVariables.Count -gt 1) {
        Write-Note "Split across $($certVariables.Count) variables (chunk size $ChunkSize)."
    }

    # ---- Optionally remove the certificate from this machine ----
    $certInStore = "Yes - $Script:CertStore on $env:COMPUTERNAME"
    if ($RemoveCertificateFromStore) {
        try {
            Remove-Item -Path (Join-Path $Script:CertStore $certificate.Thumbprint) -Force -DeleteKey -ErrorAction Stop
            $certInStore = 'No - removed from this machine after export'
            Write-Ok 'Certificate removed from the local store.'
            Write-Warn 'It cannot be re-exported. The output file is now the only copy.'
        }
        catch {
            Write-Warn "Could not remove the certificate from the store: $($_.Exception.Message)"
        }
    }

    # ---- Report ----
    Write-Step 'Writing the results file'
    $setup = [pscustomobject]@{
        TenantId           = $tenantId
        TenantName         = $tenantName
        SignedInAs         = $context.Account
        DisplayName        = $DisplayName
        AppId              = $app.AppId
        AppObjectId        = $app.Id
        ServicePrincipalId = $clientSp.Id
        Permissions        = $permissionReport
        ConsentFailed      = $consentFailed
        CertThumbprint     = $certificate.Thumbprint
        CertSubject        = $certificate.Subject
        CertNotBefore      = $certificate.NotBefore.ToString('yyyy-MM-dd')
        CertNotAfter       = $certificate.NotAfter.ToString('yyyy-MM-dd')
        CertPassword       = $plainPassword
        CertInStore        = $certInStore
        CertVariables      = $certVariables
        Verification       = $verification
        Transcript         = $Script:Transcript
    }

    $written = Write-SetupReport -Setup $setup -Path $OutFile

    # ---- Console summary ----
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host '  Setup complete' -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host ''
    Write-Host "  Tenant ID   : $tenantId"
    Write-Host "  App ID      : $($app.AppId)"
    Write-Host "  Certificate : $($certificate.Thumbprint) (expires $($certificate.NotAfter.ToString('yyyy-MM-dd')))"
    Write-Host ''

    if ($verification.GraphReadOk) {
        Write-Host '  Verified end to end: app-only token + live Autopilot read both succeeded.' -ForegroundColor Green
    }
    elseif ($consentFailed.Count -gt 0) {
        Write-Host '  ACTION REQUIRED: grant admin consent, then verify before rolling out.' -ForegroundColor Yellow
    }
    else {
        Write-Host '  NOT VERIFIED: see the results file before rolling out.' -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host "  Results written to:" -ForegroundColor White
    Write-Host "    $written" -ForegroundColor White
    Write-Host ''
    Write-Host '  That file contains the private key and the .pfx password. Create the Datto' -ForegroundColor Yellow
    Write-Host '  variables from section 5, then delete it or vault it.' -ForegroundColor Yellow
    Write-Host ''

    return 0
}

#endregion

$exit = 1
try {
    $exit = if ($VerifyOnly) { Invoke-VerifyOnly } else { Invoke-Setup }
}
catch {
    Write-Host ''
    Write-Host "  $(if ($VerifyOnly) { 'VERIFICATION FAILED' } else { 'SETUP FAILED' }): $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ''
    Write-Host "  At line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line -replace '\s+', ' ')" -ForegroundColor DarkGray
    Write-Host ''

    # Only send someone hunting for leftovers when this run could actually have created some.
    if (-not $VerifyOnly) {
        Write-Host '  Nothing further was created. If a certificate or app registration was made' -ForegroundColor Yellow
        Write-Host '  before the failure, remove it in Entra ID / Cert:\LocalMachine\My before' -ForegroundColor Yellow
        Write-Host '  re-running, so you do not accumulate half-built registrations.' -ForegroundColor Yellow
        Write-Host ''
    }

    $exit = 1
}
finally {
    try { $null = Disconnect-MgGraph -ErrorAction SilentlyContinue } catch { }
}

exit $exit
