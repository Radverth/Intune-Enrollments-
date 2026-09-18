<#
.SYNOPSIS
    Turns an authentication certificate into the base64 string(s) to paste into Datto RMM
    variables.

.DESCRIPTION
    Datto RMM cannot accept a file as a component variable, so the .pfx that
    Invoke-AutopilotBulkEnroll.ps1 authenticates with has to arrive as text. This script
    produces that text, either from a .pfx on disk or by exporting a certificate straight out
    of Cert:\LocalMachine\My by thumbprint.

    It also verifies the result end to end before you paste it anywhere: it decodes the
    base64 back, loads the certificate, and signs a test payload with the private key using
    the same RS256 operation the component performs against Entra ID. A string that fails
    here would fail on every endpoint in the bulk run.

.PARAMETER Thumbprint
    Thumbprint of a certificate in Cert:\LocalMachine\My to export. Requires elevation.

.PARAMETER PfxPath
    Path to an existing .pfx instead of exporting from the store.

.PARAMETER Password
    Password protecting the .pfx. When exporting by thumbprint this is the password applied
    to the export. Strongly recommended -- it is the only thing protecting the private key in
    transit and at rest in the RMM variable.

.PARAMETER ChunkSize
    Split the base64 across multiple variables of at most this many characters. Use this if
    the Datto RMM variable field rejects the full string for being too long. 0 (default)
    emits a single value.

.PARAMETER OutFile
    Also write the output to this file. Handy when the string is too long to copy out of a
    console window reliably.

.EXAMPLE
    .\New-AutopilotCertVariable.ps1 -Thumbprint A1B2C3... -Password (Read-Host -AsSecureString)

.EXAMPLE
    .\New-AutopilotCertVariable.ps1 -PfxPath .\autopilot.pfx -Password $pw -ChunkSize 2000
#>

[CmdletBinding(DefaultParameterSetName = 'FromStore')]
param(
    [Parameter(Mandatory, ParameterSetName = 'FromStore')]
    [string]$Thumbprint,

    [Parameter(Mandatory, ParameterSetName = 'FromFile')]
    [string]$PfxPath,

    [System.Security.SecureString]$Password,

    [ValidateRange(0, 100000)]
    [int]$ChunkSize = 0,

    [string]$OutFile
)

$ErrorActionPreference = 'Stop'

function Write-Info    { param([string]$Message) Write-Host $Message }
function Write-Good    { param([string]$Message) Write-Host $Message -ForegroundColor Green }
function Write-Warn    { param([string]$Message) Write-Host $Message -ForegroundColor Yellow }
function Write-Bad     { param([string]$Message) Write-Host $Message -ForegroundColor Red }

function ConvertFrom-SecureStringPlain {
    # Needed because the X509Certificate2 constructor and Export() both take a plain string
    # or a SecureString depending on the runtime; normalising to plain text keeps both paths
    # working on 5.1 and 7.
    param([System.Security.SecureString]$Secure)

    if (-not $Secure) { return '' }

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try   { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

$plainPassword = ConvertFrom-SecureStringPlain -Secure $Password

if ([string]::IsNullOrEmpty($plainPassword)) {
    Write-Warn 'No password was supplied. The private key will be unprotected inside the Datto variable.'
    Write-Warn 'Anyone who can read the variable gets a credential with device-management rights in your tenant.'
    Write-Host ''
}

# ---- Obtain the PFX bytes ---------------------------------------------------
$pfxBytes = $null

if ($PSCmdlet.ParameterSetName -eq 'FromStore') {
    $clean = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($clean -notmatch '^[0-9A-F]{40}$') {
        Write-Bad "'$Thumbprint' is not a 40-character hex thumbprint."
        exit 1
    }

    $certPath = "Cert:\LocalMachine\My\$clean"
    if (-not (Test-Path -LiteralPath $certPath)) {
        Write-Bad "No certificate with thumbprint $clean was found in Cert:\LocalMachine\My."
        Write-Info 'Run this on the machine where the certificate was created, elevated.'
        exit 1
    }

    $cert = Get-Item -LiteralPath $certPath
    if (-not $cert.HasPrivateKey) {
        Write-Bad 'That certificate has no private key, so it cannot be used for app-only authentication.'
        exit 1
    }

    Write-Info "Exporting $clean ($($cert.Subject))..."
    try {
        $pfxBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $plainPassword)
    }
    catch {
        Write-Bad "Export failed: $($_.Exception.Message)"
        Write-Info 'If the key was created non-exportable it cannot be moved to other machines; create a new certificate instead.'
        exit 1
    }
}
else {
    if (-not (Test-Path -LiteralPath $PfxPath)) {
        Write-Bad "'$PfxPath' does not exist."
        exit 1
    }
    Write-Info "Reading $PfxPath..."
    $pfxBytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $PfxPath).Path)
}

$base64 = [Convert]::ToBase64String($pfxBytes)
Write-Info "PFX is $($pfxBytes.Length) bytes; base64 is $($base64.Length) characters."
Write-Host ''

# ---- Verify before anyone pastes it anywhere --------------------------------
# A truncated or wrong-password string produces a bulk run that fails on every single
# endpoint, so prove the round trip here instead.
Write-Info 'Verifying the encoded certificate...'
$verifyCert = $null
try {
    $decoded = [Convert]::FromBase64String($base64)
    if ($decoded.Length -ne $pfxBytes.Length) { throw 'decoded length does not match the source' }

    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
    if ([enum]::GetNames([System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]) -contains 'EphemeralKeySet') {
        $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
    }

    $verifyCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($decoded, $plainPassword, $flags)

    if (-not $verifyCert.HasPrivateKey) { throw 'the decoded certificate has no private key' }

    # Exercise the exact signing operation the component uses for its client assertion.
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($verifyCert)
    if (-not $rsa) { throw 'the private key could not be opened for signing' }

    $probe = [Text.Encoding]::UTF8.GetBytes('autopilot-client-assertion-probe')
    $signature = $rsa.SignData($probe, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    if (-not $rsa.VerifyData($probe, $signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)) {
        throw 'the RS256 signature did not verify'
    }

    Write-Good '  Round trip OK -- decoded, private key present, RS256 signing verified.'
    Write-Info  "  Thumbprint : $($verifyCert.Thumbprint)"
    Write-Info  "  Subject    : $($verifyCert.Subject)"
    Write-Info  "  Expires    : $($verifyCert.NotAfter.ToString('yyyy-MM-dd')) ($([int]([math]::Floor(($verifyCert.NotAfter - (Get-Date)).TotalDays))) days)"

    if ($verifyCert.NotAfter -lt (Get-Date).AddDays(60)) {
        Write-Warn '  This certificate expires soon. Every endpoint using it will start failing on that date.'
    }
}
catch {
    Write-Bad "  Verification FAILED: $($_.Exception.Message)"
    Write-Info '  Not emitting a variable value that would fail on every endpoint. Fix the source certificate or password and re-run.'
    exit 1
}
finally {
    if ($verifyCert) { $verifyCert.Dispose() }
}

Write-Host ''

# ---- Emit the variable value(s) ---------------------------------------------
$lines = @()

if ($ChunkSize -gt 0 -and $base64.Length -gt $ChunkSize) {
    $parts = [Math]::Ceiling($base64.Length / $ChunkSize)
    Write-Info "Splitting across $parts variables of up to $ChunkSize characters each."
    Write-Host ''

    for ($i = 0; $i -lt $parts; $i++) {
        $start  = $i * $ChunkSize
        $length = [Math]::Min($ChunkSize, $base64.Length - $start)
        $name   = if ($i -eq 0) { 'AutopilotCertBase64' } else { "AutopilotCertBase64_$($i + 1)" }
        $lines += "$name=$($base64.Substring($start, $length))"
    }

    Write-Warn 'Create these variables in order. The component stops reassembling at the first gap,'
    Write-Warn 'so a missing middle part silently truncates the certificate.'
}
else {
    if ($ChunkSize -gt 0) {
        Write-Info "The base64 is shorter than the $ChunkSize-character chunk size, so a single variable is enough."
    }
    $lines += "AutopilotCertBase64=$base64"
}

Write-Host ''
Write-Host ('=' * 72)
Write-Host '  Datto RMM variables to create'
Write-Host ('=' * 72)
Write-Host ''

foreach ($line in $lines) {
    $name, $value = $line -split '=', 2
    Write-Host "  $name" -ForegroundColor Cyan
    Write-Host "  $value"
    Write-Host ''
}

if ($OutFile) {
    try {
        $lines | Set-Content -LiteralPath $OutFile -Encoding UTF8
        Write-Good "Also written to $OutFile"
        Write-Warn 'That file contains the private key -- delete it once the variables are created.'
    }
    catch {
        Write-Bad "Could not write '$OutFile': $($_.Exception.Message)"
    }
}

Write-Host ''
Write-Info 'Remaining variables to set on the component: AutopilotTenantId, AutopilotAppId,'
Write-Info "and AutopilotCertPassword$(if ([string]::IsNullOrEmpty($plainPassword)) { ' (not needed -- no password was set)' } else { '' })."
Write-Host ''
