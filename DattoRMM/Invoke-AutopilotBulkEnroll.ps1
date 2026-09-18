<#
.SYNOPSIS
    Datto RMM component: registers the device it runs on with Windows Autopilot / Intune.

.DESCRIPTION
    Non-interactive counterpart to Invoke-IntuneAutopilotEnroll.ps1, built to be deployed as
    a Datto RMM component against a whole site or device group for bulk enrollment.

    Everything is supplied through Datto RMM component/site/account variables -- there are no
    prompts and no menus. Because Datto RMM cannot take a file as a variable, the
    authentication certificate arrives as a base64 string (the .pfx, base64-encoded), which
    the script decodes in memory.

    Deliberately dependency-free: it does NOT install or import the Microsoft.Graph modules
    and does NOT use Get-WindowsAutopilotInfo.ps1. Both would mean an Install-Module /
    Install-Script (and therefore a PowerShell Gallery round trip and a NuGet bootstrap) on
    every endpoint, running as SYSTEM and non-interactive -- a per-device failure mode that
    does not belong in a bulk job. Instead it signs its own client assertion with the
    certificate and calls the Graph REST API directly, using nothing but .NET and
    Invoke-RestMethod.

    The certificate is never written to the certificate store or to disk, and its private key
    is disposed before the script exits.

.NOTES
    Runs as SYSTEM under the Datto RMM agent. Windows PowerShell 5.1 or PowerShell 7.
    Exit codes are documented in DattoRMM/README.md and are what Datto uses to decide
    whether the job succeeded.
#>

[CmdletBinding()]
param()

#region --------------------------------------------------------------- 64-bit relaunch

# The Datto RMM agent can invoke components in a 32-bit PowerShell on a 64-bit OS. The
# Autopilot hardware hash lives in the root\cimv2\mdm\dmmap WMI namespace, which a 32-bit
# process cannot reliably reach, so re-launch through SysNative before doing anything else.
# The env-var guard stops this from recursing if the relaunch itself is still 32-bit.
if ([Environment]::Is64BitOperatingSystem -and
    -not [Environment]::Is64BitProcess -and
    -not $env:AUTOPILOT_BULK_RELAUNCHED) {

    $native = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $native) {
        Write-Host 'Running in a 32-bit process on a 64-bit OS -- relaunching under 64-bit PowerShell.'
        $env:AUTOPILOT_BULK_RELAUNCHED = '1'
        & $native -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
        exit $LASTEXITCODE
    }

    Write-Host "WARNING: 32-bit process and '$native' was not found -- continuing, but the hardware hash may not be readable."
}

#endregion

#region --------------------------------------------------------------- Constants

$Script:ComponentName = 'Autopilot Bulk Enroll (Datto RMM)'
$Script:ComponentVer  = '1.0.0'
$Script:DataRoot      = 'C:\ProgramData\AffinityIT\IntuneAutopilotEnroll'
$Script:LogPath       = Join-Path $Script:DataRoot 'bulk-enroll.log'

# Exit codes. Datto treats any non-zero as a failed job.
$Script:ExitSuccess       = 0
$Script:ExitConfigError   = 1
$Script:ExitCertError     = 2
$Script:ExitAuthError     = 3
$Script:ExitHardwareError = 4
$Script:ExitImportError   = 5
$Script:ExitPartial       = 6   # registered, but a follow-up step (rename) did not complete
$Script:ExitUnexpected    = 7

# Per-cloud endpoints. Autopilot exists in the sovereign clouds and the hostnames differ.
$Script:CloudEndpoints = @{
    'Global'   = @{ Login = 'https://login.microsoftonline.com'; Graph = 'https://graph.microsoft.com' }
    'USGov'    = @{ Login = 'https://login.microsoftonline.us';  Graph = 'https://graph.microsoft.us' }
    'USGovDoD' = @{ Login = 'https://login.microsoftonline.us';  Graph = 'https://dod-graph.microsoft.us' }
    'China'    = @{ Login = 'https://login.chinacloudapi.cn';    Graph = 'https://microsoftgraph.chinacloudapi.cn' }
}

$Script:Result = [ordered]@{
    Status       = 'NotStarted'
    Serial       = ''
    GroupTag     = ''
    ComputerName = ''
    Message      = ''
}

#endregion

#region --------------------------------------------------------------- Logging / output

function Initialize-Log {
    [CmdletBinding()]
    param()

    try {
        if (-not (Test-Path -LiteralPath $Script:DataRoot)) {
            $null = New-Item -Path $Script:DataRoot -ItemType Directory -Force -ErrorAction Stop
        }
    }
    catch {
        Write-Host "WARNING: could not create '$Script:DataRoot' -- logging to stdout only. $($_.Exception.Message)"
    }
}

function Write-Log {
    <#
        Writes to the Datto RMM activity log (stdout) and to a local file. Everything the
        technician needs to diagnose a failed bulk run should be visible in the Datto job
        output without having to remote onto the device.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][AllowEmptyString()][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'DEBUG')][string]$Level = 'INFO'
    )

    # .NET exception messages are frequently multi-line, which would break the one-event-
    # per-line shape the Datto activity log is read and grepped in.
    $flat  = ($Message -replace '\r?\n', ' ') -replace ' {2,}', ' '
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line  = '{0} [{1,-7}] {2}' -f $stamp, $Level, $flat

    Write-Host $line

    try {
        Add-Content -LiteralPath $Script:LogPath -Value $line -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        # Never let logging break a bulk run.
    }
}

function Write-DattoResult {
    <#
        Datto RMM scrapes stdout between these markers into the component's result field, so
        the device list can be filtered and sorted on the outcome instead of opening each job.
    #>
    [CmdletBinding()]
    param()

    Write-Host '<-Start Result->'
    foreach ($key in $Script:Result.Keys) {
        $value = $Script:Result[$key]
        if ([string]::IsNullOrWhiteSpace([string]$value)) { continue }
        # Result lines are Key=Value, so newlines and '=' in the value would corrupt the block.
        $clean = ([string]$value) -replace '[\r\n]+', ' ' -replace '=', '-'
        Write-Host ("Autopilot{0}={1}" -f $key, $clean)
    }
    Write-Host '<-End Result->'
}

#endregion

#region --------------------------------------------------------------- Variables

function Get-RmmVariable {
    <#
        Reads a Datto RMM variable. Component input variables surface as environment
        variables named exactly as defined in the component; the usr/usr_ fallbacks are
        cheap insurance against a component that was set up with a prefixed name.

        Datto also has a habit of passing the literal strings 'null' and '""' for a variable
        that was left blank, so those are normalised to empty.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Default = ''
    )

    foreach ($candidate in @($Name, "usr$Name", "usr_$Name")) {
        $value = [Environment]::GetEnvironmentVariable($candidate)
        if ($null -eq $value) { continue }

        $value = $value.Trim().Trim('"')
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        if ($value -in @('null', 'undefined', '-')) { continue }

        return $value
    }

    return $Default
}

function Get-RmmBooleanVariable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [bool]$Default = $false
    )

    $raw = Get-RmmVariable -Name $Name
    if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }

    switch -Regex ($raw.ToLowerInvariant()) {
        '^(1|true|yes|y|on|enabled)$'   { return $true }
        '^(0|false|no|n|off|disabled)$' { return $false }
        default {
            Write-Log -Message "Variable '$Name' has value '$raw', which is not a yes/no -- using the default ($Default)." -Level WARN
            return $Default
        }
    }
}

function Get-CertificateBase64FromVariables {
    <#
        Reassembles the base64 .pfx from AutopilotCertBase64 plus any numbered continuation
        variables (AutopilotCertBase64_2, _3, ...).

        The split exists because a base64-encoded PFX is a few thousand characters and some
        RMM variable fields cap input length. Splitting across variables sidesteps that
        without needing a file upload, which Datto RMM does not support.
    #>
    [CmdletBinding()]
    param()

    $parts = @()

    $first = Get-RmmVariable -Name 'AutopilotCertBase64'
    if (-not [string]::IsNullOrWhiteSpace($first)) { $parts += $first }

    for ($i = 2; $i -le 20; $i++) {
        $next = Get-RmmVariable -Name "AutopilotCertBase64_$i"
        if ([string]::IsNullOrWhiteSpace($next)) { break }
        $parts += $next
    }

    if ($parts.Count -eq 0) { return '' }
    if ($parts.Count -gt 1) {
        Write-Log -Message "Reassembled the certificate from $($parts.Count) variable parts."
    }

    # Strip whitespace/newlines a copy-paste may have introduced.
    return (($parts -join '') -replace '\s', '')
}

#endregion

#region --------------------------------------------------------------- Certificate

function Get-CertificateFromBase64 {
    <#
        Decodes the base64 .pfx into an in-memory X509Certificate2.

        The certificate is intentionally never imported into Cert:\LocalMachine\My. A bulk
        run touches every endpoint in a site, and a persisted private key would leave a
        credential with tenant-wide device-management rights on all of them, readable by any
        local administrator. Keeping it in memory for the life of the script and disposing it
        afterwards keeps the blast radius to the run itself.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Base64,
        [AllowEmptyString()][string]$Password = ''
    )

    $bytes = $null
    try {
        $bytes = [Convert]::FromBase64String($Base64)
    }
    catch {
        Write-Log -Message 'The certificate variable is not valid base64. Re-generate it with New-AutopilotCertVariable.ps1 and check for truncation or a missing continuation part.' -Level ERROR
        return $null
    }

    Write-Log -Message "Decoded $($bytes.Length) bytes of certificate data." -Level DEBUG

    # EphemeralKeySet keeps the key entirely out of the filesystem, but it only exists on
    # .NET Core / PowerShell 7. On Windows PowerShell 5.1 fall back to a non-persisted
    # machine keyset, which is removed when the certificate is disposed.
    $flagSets = @()
    if ([enum]::GetNames([System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]) -contains 'EphemeralKeySet') {
        $flagSets += [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
    }
    $flagSets += [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet

    $secure = $null
    if (-not [string]::IsNullOrEmpty($Password)) {
        $secure = ConvertTo-SecureString -String $Password -AsPlainText -Force
    }

    foreach ($flags in $flagSets) {
        try {
            $cert = if ($secure) {
                New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($bytes, $secure, $flags)
            }
            else {
                New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($bytes, '', $flags)
            }

            if (-not $cert.HasPrivateKey) {
                Write-Log -Message 'The supplied certificate has no private key. Export the .pfx with the private key included -- a .cer/.crt will not work for app-only auth.' -Level ERROR
                $cert.Dispose()
                return $null
            }

            Write-Log -Message "Loaded certificate $($cert.Thumbprint) ($($cert.Subject)), expires $($cert.NotAfter.ToString('yyyy-MM-dd'))." -Level SUCCESS

            if ($cert.NotAfter -lt (Get-Date)) {
                Write-Log -Message "This certificate EXPIRED on $($cert.NotAfter.ToString('yyyy-MM-dd')) -- authentication will fail. Rotate it and update the Datto variable." -Level ERROR
                $cert.Dispose()
                return $null
            }
            if ($cert.NotAfter -lt (Get-Date).AddDays(30)) {
                Write-Log -Message "This certificate expires on $($cert.NotAfter.ToString('yyyy-MM-dd')) -- rotate it soon." -Level WARN
            }

            return $cert
        }
        catch {
            $message = $_.Exception.Message
            Write-Log -Message "Certificate load attempt failed with flags '$flags': $message" -Level DEBUG

            if ($message -match 'password|The specified network password is not correct') {
                Write-Log -Message 'The certificate password appears to be wrong. Check the AutopilotCertPassword variable.' -Level ERROR
                return $null
            }
        }
    }

    Write-Log -Message 'The certificate could not be loaded from the supplied base64 data.' -Level ERROR
    return $null
}

#endregion

#region --------------------------------------------------------------- Auth (client assertion)

function ConvertTo-Base64Url {
    # JWT segments are base64url: '+' and '/' swapped out, padding stripped.
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)

    return ([Convert]::ToBase64String($Bytes).TrimEnd('=') -replace '\+', '-' -replace '/', '_')
}

function Get-CertificateRsaPrivateKey {
    <#
        RSACertificateExtensions is the modern accessor and works on .NET Framework 4.6+ and
        .NET Core. The .PrivateKey fallback covers older framework builds, where it only
        supports SHA256 signing if the key lives in a CNG/Enhanced provider -- which is why
        the companion tool creates certificates with the Enhanced RSA and AES provider.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Certificate)

    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        if ($rsa) { return $rsa }
    }
    catch {
        Write-Log -Message "RSACertificateExtensions::GetRSAPrivateKey failed: $($_.Exception.Message)" -Level DEBUG
    }

    try {
        if ($Certificate.PrivateKey) { return $Certificate.PrivateKey }
    }
    catch {
        Write-Log -Message "Certificate.PrivateKey failed: $($_.Exception.Message)" -Level DEBUG
    }

    return $null
}

function New-ClientAssertion {
    <#
        Builds and signs the RS256 JWT that stands in for a client secret in the
        certificate-credential OAuth flow. Doing this by hand is what lets the component run
        with no MSAL/Graph module present on the endpoint.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Certificate,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$LoginHost
    )

    $rsa = Get-CertificateRsaPrivateKey -Certificate $Certificate
    if (-not $rsa) {
        Write-Log -Message 'The certificate private key could not be opened for signing.' -Level ERROR
        return $null
    }

    $now       = [DateTimeOffset]::UtcNow
    $audience  = "$LoginHost/$TenantId/oauth2/v2.0/token"

    # x5t identifies which of the app registration's certificates signed this assertion.
    $header = [ordered]@{
        alg = 'RS256'
        typ = 'JWT'
        x5t = (ConvertTo-Base64Url -Bytes $Certificate.GetCertHash())
    }

    $payload = [ordered]@{
        aud = $audience
        iss = $ClientId
        sub = $ClientId
        jti = [guid]::NewGuid().ToString()
        # A little backdating absorbs clock skew between the endpoint and Entra ID, which is
        # a real problem on freshly imaged machines that have not synced time yet.
        nbf = [int64]$now.AddMinutes(-5).ToUnixTimeSeconds()
        exp = [int64]$now.AddMinutes(10).ToUnixTimeSeconds()
    }

    $encoder     = [System.Text.Encoding]::UTF8
    $headerPart  = ConvertTo-Base64Url -Bytes $encoder.GetBytes(($header  | ConvertTo-Json -Compress))
    $payloadPart = ConvertTo-Base64Url -Bytes $encoder.GetBytes(($payload | ConvertTo-Json -Compress))
    $unsigned    = "$headerPart.$payloadPart"

    try {
        $signature = $rsa.SignData(
            $encoder.GetBytes($unsigned),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
    }
    catch {
        Write-Log -Message "Signing the client assertion failed: $($_.Exception.Message)" -Level ERROR
        Write-Log -Message 'This usually means the private key is held in a provider that cannot do SHA256. Re-create the certificate with the Microsoft Enhanced RSA and AES Cryptographic Provider.' -Level ERROR
        return $null
    }

    return "$unsigned.$(ConvertTo-Base64Url -Bytes $signature)"
}

function Get-GraphAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Certificate,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$LoginHost,
        [Parameter(Mandatory)][string]$GraphHost
    )

    $assertion = New-ClientAssertion -Certificate $Certificate -TenantId $TenantId -ClientId $ClientId -LoginHost $LoginHost
    if (-not $assertion) { return $null }

    $body = @{
        client_id             = $ClientId
        client_assertion      = $assertion
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        scope                 = "$GraphHost/.default"
        grant_type            = 'client_credentials'
    }

    try {
        Write-Log -Message "Requesting an app-only access token from $LoginHost..."
        $response = Invoke-RestMethod -Method Post `
                                      -Uri "$LoginHost/$TenantId/oauth2/v2.0/token" `
                                      -Body $body `
                                      -ContentType 'application/x-www-form-urlencoded' `
                                      -ErrorAction Stop

        Write-Log -Message 'Access token acquired.' -Level SUCCESS
        return $response.access_token
    }
    catch {
        Write-Log -Message "Token request failed: $($_.Exception.Message)" -Level ERROR

        $detail = Get-HttpErrorBody -ErrorRecord $_
        if ($detail) { Write-Log -Message "Entra ID returned: $detail" -Level ERROR }

        Show-AuthFailureHints -Detail "$($_.Exception.Message) $detail"
        return $null
    }
}

function Show-AuthFailureHints {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Detail)

    switch -Regex ($Detail) {
        'AADSTS700027|AADSTS700024|invalid_client|assertion' {
            Write-Log -Message 'HINT: the certificate public key is probably not on the app registration, or you exported a different certificate than the one uploaded. Check Entra ID > App registrations > your app > Certificates & secrets and compare thumbprints.' -Level ERROR
        }
        'AADSTS7000215|AADSTS70021' {
            Write-Log -Message 'HINT: the app registration rejected the credential. Confirm AutopilotAppId matches the app the certificate belongs to.' -Level ERROR
        }
        'AADSTS90002|AADSTS900023' {
            Write-Log -Message 'HINT: the tenant ID does not resolve. Check AutopilotTenantId.' -Level ERROR
        }
        'AADSTS700016|application.*not found' {
            Write-Log -Message 'HINT: no app registration with that AppId exists in this tenant.' -Level ERROR
        }
    }
}

function Get-HttpErrorBody {
    <#
        Graph and Entra ID put the useful part of a failure in the response body, which
        Invoke-RestMethod does not surface in the exception message. PowerShell 7 hands it
        over directly; 5.1 needs the stream read manually.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        return ($ErrorRecord.ErrorDetails.Message -replace '\s+', ' ')
    }

    try {
        $response = $ErrorRecord.Exception.Response
        if (-not $response) { return '' }

        if ($response -is [System.Net.HttpWebResponse]) {
            $stream = $response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            try   { return (($reader.ReadToEnd()) -replace '\s+', ' ') }
            finally { $reader.Dispose() }
        }
    }
    catch {
        Write-Log -Message "Could not read the HTTP error body: $($_.Exception.Message)" -Level DEBUG
    }

    return ''
}

function Get-HttpStatusCode {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    try {
        $response = $ErrorRecord.Exception.Response
        if ($response -and $response.StatusCode) { return [int]$response.StatusCode }
    }
    catch {
        # Fall through.
    }
    return 0
}

function Get-RetryAfterSeconds {
    <#
        Reads the Retry-After header from a throttled response.

        The two runtimes expose it differently and neither is forgiving: Windows PowerShell
        hands back a WebHeaderCollection, which has a string indexer, while PowerShell 7 hands
        back HttpResponseHeaders, which does not -- indexing it by name throws. Getting this
        wrong silently discards the server's own backoff guidance, which is exactly the
        guidance that matters when a bulk run is being throttled.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord,
        [int]$Default = 10
    )

    $raw = $null

    try {
        $headers = $ErrorRecord.Exception.Response.Headers
        if ($headers) {
            # PowerShell 7 / HttpResponseHeaders
            if ($headers -is [System.Net.Http.Headers.HttpResponseHeaders]) {
                $values = $null
                if ($headers.TryGetValues('Retry-After', [ref]$values)) {
                    $raw = @($values)[0]
                }
            }
            else {
                # Windows PowerShell / WebHeaderCollection
                $raw = $headers['Retry-After']
            }
        }
    }
    catch {
        # Header genuinely unavailable; fall through to the default.
    }

    $seconds = 0
    if ($raw -and [int]::TryParse(([string]$raw).Trim(), [ref]$seconds) -and $seconds -gt 0) {
        # Guard against a server telling us to sleep for an unreasonable length of time
        # inside an RMM job that has its own timeout.
        if ($seconds -gt 300) { return 300 }
        return $seconds
    }

    return $Default
}

function Invoke-GraphRequest {
    <#
        Thin Graph wrapper with retry. A bulk run can put hundreds of devices through the
        same tenant at once, so 429 throttling is expected rather than exceptional and is
        retried honouring Retry-After. 5xx gets the same treatment; 4xx is returned to the
        caller because retrying a bad request never helps.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$AccessToken,
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')][string]$Method = 'GET',
        $Body,
        [int]$MaxAttempts = 4
    )

    $headers = @{
        Authorization = "Bearer $AccessToken"
        Accept        = 'application/json'
    }

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $params = @{
                Method      = $Method
                Uri         = $Uri
                Headers     = $headers
                ErrorAction = 'Stop'
            }
            if ($null -ne $Body) {
                $params.Body        = ($Body | ConvertTo-Json -Depth 6 -Compress)
                $params.ContentType = 'application/json'
            }

            return Invoke-RestMethod @params
        }
        catch {
            $status = Get-HttpStatusCode -ErrorRecord $_
            $detail = Get-HttpErrorBody   -ErrorRecord $_

            $retryable = ($status -eq 429 -or $status -ge 500 -or $status -eq 0)
            if (-not $retryable -or $attempt -eq $MaxAttempts) {
                Write-Log -Message "Graph $Method $Uri failed (HTTP $status): $($_.Exception.Message)" -Level ERROR
                if ($detail) { Write-Log -Message "Graph returned: $detail" -Level ERROR }
                throw
            }

            # Prefer the server's own backoff guidance when it sends one.
            $wait = Get-RetryAfterSeconds -ErrorRecord $_ -Default (5 * $attempt)

            Write-Log -Message "Graph $Method returned HTTP $status -- retrying in ${wait}s (attempt $attempt of $MaxAttempts)." -Level WARN
            Start-Sleep -Seconds $wait
        }
    }
}

#endregion

#region --------------------------------------------------------------- Device information

function Get-DeviceHardwareInfo {
    <#
        Pulls the serial and the Autopilot hardware hash. DeviceHardwareData is already a
        base64 string, which is exactly what the import API's hardwareIdentifier wants.
    #>
    [CmdletBinding()]
    param()

    $info = [pscustomobject]@{
        SerialNumber = ''
        HardwareHash = ''
        Manufacturer = ''
        Model        = ''
    }

    try {
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $info.SerialNumber = ([string]$bios.SerialNumber).Trim()
    }
    catch {
        Write-Log -Message "Could not read the BIOS serial number: $($_.Exception.Message)" -Level ERROR
    }

    try {
        $system = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $info.Manufacturer = ([string]$system.Manufacturer).Trim()
        $info.Model        = ([string]$system.Model).Trim()
    }
    catch {
        Write-Log -Message "Could not read the computer system info: $($_.Exception.Message)" -Level DEBUG
    }

    try {
        $devDetail = Get-CimInstance -Namespace 'root/cimv2/mdm/dmmap' `
                                     -ClassName 'MDM_DevDetail_Ext01' `
                                     -Filter "InstanceID='Ext' AND ParentID='./DevDetail'" `
                                     -ErrorAction Stop
        $info.HardwareHash = ([string]$devDetail.DeviceHardwareData).Trim()
    }
    catch {
        Write-Log -Message "Could not read the Autopilot hardware hash: $($_.Exception.Message)" -Level ERROR
    }

    return $info
}

function Test-HardwareInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Info)

    $ok = $true

    if ([string]::IsNullOrWhiteSpace($Info.SerialNumber)) {
        Write-Log -Message 'This device reports no BIOS serial number, which Autopilot requires.' -Level ERROR
        $ok = $false
    }
    elseif ($Info.SerialNumber -match '^(0|None|Default string|To be filled by O\.E\.M\.|System Serial Number)$') {
        # Common on whitebox and VM hardware. Autopilot keys off the serial, so a placeholder
        # value will either be rejected or collide with every other device like it.
        Write-Log -Message "This device's serial number is the placeholder '$($Info.SerialNumber)'. Autopilot identifies devices by serial, so registration will be unreliable or will collide with other devices reporting the same value." -Level ERROR
        $ok = $false
    }

    if ([string]::IsNullOrWhiteSpace($Info.HardwareHash)) {
        Write-Log -Message 'No Autopilot hardware hash is available on this device. Common causes: it is a VM that cannot produce one, the OS build is too old, or the WMI call was blocked.' -Level ERROR
        $ok = $false
    }

    return $ok
}

function Test-AlreadyRegistered {
    <#
        Bulk jobs get re-run -- against a whole site, on a schedule, or after a partial
        failure. Checking first keeps the Datto output meaningful (Skipped vs Registered)
        and avoids hammering the import API with devices that are already done.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SerialNumber,
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$GraphHost
    )

    try {
        # Serials can contain characters that need escaping in an OData string literal.
        $escaped = $SerialNumber -replace "'", "''"
        $uri     = "$GraphHost/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$escaped')"

        $response = Invoke-GraphRequest -Uri $uri -AccessToken $AccessToken -Method GET
        $match    = @($response.value | Where-Object { $_.serialNumber -eq $SerialNumber })

        if ($match.Count -gt 0) {
            Write-Log -Message "Serial $SerialNumber is already registered in Autopilot (group tag: '$($match[0].groupTag)')."
            return $true
        }

        Write-Log -Message "Serial $SerialNumber is not yet registered in Autopilot." -Level DEBUG
        return $false
    }
    catch {
        # A failed pre-check must not stop the enrollment -- the import itself is the
        # authority. Worst case we re-import a device, which Autopilot tolerates.
        Write-Log -Message "Could not check whether this device is already registered, continuing with the import anyway: $($_.Exception.Message)" -Level WARN
        return $false
    }
}

function Expand-NameToken {
    <#
        Lets a single Datto variable express a naming convention across a whole site,
        e.g. 'WS-%SERIAL%'. Autopilot/NetBIOS caps the name at 15 characters.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Template,
        [Parameter(Mandatory)]$HardwareInfo
    )

    $name = $Template
    $name = $name -replace '%SERIAL%',   $HardwareInfo.SerialNumber
    $name = $name -replace '%HOSTNAME%', $env:COMPUTERNAME
    $name = $name.Trim()

    if ($name.Length -gt 15) {
        $truncated = $name.Substring(0, 15)
        Write-Log -Message "Computer name '$name' exceeds the 15-character limit -- truncating to '$truncated'." -Level WARN
        $name = $truncated
    }

    return $name
}

#endregion

#region --------------------------------------------------------------- Autopilot import

function Invoke-AutopilotImport {
    <#
        Posts the device to the Autopilot import queue. groupTag and assignedUserPrincipalName
        are the only optional properties the import resource accepts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$HardwareInfo,
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$GraphHost,
        [AllowEmptyString()][string]$GroupTag = '',
        [AllowEmptyString()][string]$AssignedUser = ''
    )

    $body = @{
        '@odata.type'      = '#microsoft.graph.importedWindowsAutopilotDeviceIdentity'
        serialNumber       = $HardwareInfo.SerialNumber
        hardwareIdentifier = $HardwareInfo.HardwareHash
    }
    if (-not [string]::IsNullOrWhiteSpace($GroupTag))     { $body.groupTag                 = $GroupTag }
    if (-not [string]::IsNullOrWhiteSpace($AssignedUser)) { $body.assignedUserPrincipalName = $AssignedUser }

    Write-Log -Message "Importing serial $($HardwareInfo.SerialNumber) into Autopilot..."

    return Invoke-GraphRequest -Uri "$GraphHost/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities" `
                               -AccessToken $AccessToken `
                               -Method POST `
                               -Body $body
}

function Wait-AutopilotImport {
    <#
        The import is asynchronous. Polls the import record until the service reports a
        terminal state, and returns the registration id so the caller can set the device
        name if one was requested.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ImportId,
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$GraphHost,
        [int]$TimeoutSeconds = 180
    )

    $outcome = [pscustomobject]@{
        Completed            = $false
        Succeeded            = $false
        DeviceRegistrationId = ''
        Status               = 'unknown'
        ErrorName            = ''
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $uri      = "$GraphHost/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities/$ImportId"

    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 10

        try {
            $record = Invoke-GraphRequest -Uri $uri -AccessToken $AccessToken -Method GET
            $state  = $record.state
            $status = [string]$state.deviceImportStatus
            $outcome.Status = $status

            Write-Log -Message "Import status: $status" -Level DEBUG

            switch ($status.ToLowerInvariant()) {
                'complete' {
                    $outcome.Completed            = $true
                    $outcome.Succeeded            = $true
                    $outcome.DeviceRegistrationId = [string]$state.deviceRegistrationId
                    return $outcome
                }
                'error' {
                    $outcome.Completed = $true
                    $outcome.ErrorName = [string]$state.deviceErrorName
                    Write-Log -Message "Autopilot import failed: $($state.deviceErrorName) (code $($state.deviceErrorCode))." -Level ERROR

                    if ("$($state.deviceErrorName)" -match 'ZtdDeviceAlreadyAssigned') {
                        Write-Log -Message 'HINT: this device is already registered to Autopilot -- possibly in a different tenant. It must be deregistered there before it can be imported here.' -Level ERROR
                    }
                    return $outcome
                }
                default {
                    # 'unknown' / 'pending' -- keep waiting.
                }
            }
        }
        catch {
            Write-Log -Message "Polling the import status failed, will retry: $($_.Exception.Message)" -Level WARN
        }
    }

    Write-Log -Message "The import did not reach a terminal state within ${TimeoutSeconds}s. The device was submitted and will most likely complete on the service side -- check Intune before re-running." -Level WARN
    return $outcome
}

function Set-AutopilotDeviceName {
    <#
        The import resource has no computer-name property, so a requested name has to be
        applied afterwards against the resulting Autopilot device identity.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DeviceRegistrationId,
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$GraphHost
    )

    try {
        Write-Log -Message "Setting the Autopilot device name to '$ComputerName'..."
        $null = Invoke-GraphRequest -Uri "$GraphHost/v1.0/deviceManagement/windowsAutopilotDeviceIdentities/$DeviceRegistrationId/updateDeviceProperties" `
                                    -AccessToken $AccessToken `
                                    -Method POST `
                                    -Body @{ displayName = $ComputerName }

        Write-Log -Message "Device name set to '$ComputerName'." -Level SUCCESS
        return $true
    }
    catch {
        Write-Log -Message "The device registered successfully but the name could not be set: $($_.Exception.Message)" -Level WARN
        return $false
    }
}

#endregion

#region --------------------------------------------------------------- Datto UDF

function Set-DattoUdf {
    <#
        Writes the outcome to a Datto RMM user-defined field so a bulk run's results can be
        read off the device list and filtered, instead of opening every job's output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Number,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value
    )

    if ($Number -lt 1 -or $Number -gt 30) {
        Write-Log -Message "UDF number $Number is out of range (1-30) -- skipping the UDF write." -Level WARN
        return
    }

    try {
        $key = 'HKLM:\SOFTWARE\CentraStage'
        if (-not (Test-Path -LiteralPath $key)) {
            Write-Log -Message "The Datto RMM registry key '$key' does not exist -- skipping the UDF write." -Level WARN
            return
        }

        # UDFs are capped at 255 characters.
        $trimmed = if ($Value.Length -gt 255) { $Value.Substring(0, 255) } else { $Value }
        Set-ItemProperty -LiteralPath $key -Name "Custom$Number" -Value $trimmed -ErrorAction Stop
        Write-Log -Message "Wrote UDF $Number : $trimmed"
    }
    catch {
        Write-Log -Message "Could not write UDF $Number : $($_.Exception.Message)" -Level WARN
    }
}

#endregion

#region --------------------------------------------------------------- Main

function Invoke-Main {
    [CmdletBinding()]
    param()

    Initialize-Log

    Write-Log -Message ('=' * 70)
    Write-Log -Message "$Script:ComponentName v$Script:ComponentVer on $env:COMPUTERNAME (PowerShell $($PSVersionTable.PSVersion), 64-bit process: $([Environment]::Is64BitProcess))"

    # Windows PowerShell 5.1 still defaults to TLS 1.0/1.1, which login.microsoftonline.com
    # and graph.microsoft.com both refuse.
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch {
        Write-Log -Message "Could not force TLS 1.2: $($_.Exception.Message)" -Level WARN
    }

    # ---- Variables ---------------------------------------------------------
    $tenantId     = Get-RmmVariable -Name 'AutopilotTenantId'
    $appId        = Get-RmmVariable -Name 'AutopilotAppId'
    $certPassword = Get-RmmVariable -Name 'AutopilotCertPassword'
    $groupTag     = Get-RmmVariable -Name 'AutopilotGroupTag'
    $assignedUser = Get-RmmVariable -Name 'AutopilotAssignedUser'
    $nameTemplate = Get-RmmVariable -Name 'AutopilotAssignedComputerName'
    $cloud        = Get-RmmVariable -Name 'AutopilotCloud' -Default 'Global'
    $udfRaw       = Get-RmmVariable -Name 'AutopilotUdfNumber'
    $skipExisting = Get-RmmBooleanVariable -Name 'AutopilotSkipIfRegistered' -Default $true
    $waitRaw      = Get-RmmVariable -Name 'AutopilotImportTimeoutSeconds' -Default '180'

    $problems = @()
    if ([string]::IsNullOrWhiteSpace($tenantId)) { $problems += 'AutopilotTenantId is not set' }
    if ([string]::IsNullOrWhiteSpace($appId))    { $problems += 'AutopilotAppId is not set' }

    $parsed = [guid]::Empty
    if ($tenantId -and -not [guid]::TryParse($tenantId, [ref]$parsed)) { $problems += "AutopilotTenantId ('$tenantId') is not a GUID" }
    if ($appId    -and -not [guid]::TryParse($appId,    [ref]$parsed)) { $problems += "AutopilotAppId ('$appId') is not a GUID" }

    $certBase64 = Get-CertificateBase64FromVariables
    if ([string]::IsNullOrWhiteSpace($certBase64)) { $problems += 'AutopilotCertBase64 is not set' }

    if (-not $Script:CloudEndpoints.Contains($cloud)) {
        $problems += "AutopilotCloud ('$cloud') must be one of: $($Script:CloudEndpoints.Keys -join ', ')"
    }

    if ($problems.Count -gt 0) {
        foreach ($problem in $problems) { Write-Log -Message $problem -Level ERROR }
        Write-Log -Message 'Fix the component variables in Datto RMM and re-run. See DattoRMM/README.md.' -Level ERROR
        $Script:Result.Status  = 'ConfigError'
        $Script:Result.Message = ($problems -join '; ')
        return $Script:ExitConfigError
    }

    $loginHost = $Script:CloudEndpoints[$cloud].Login
    $graphHost = $Script:CloudEndpoints[$cloud].Graph
    Write-Log -Message "Tenant $tenantId, app $appId, cloud $cloud."

    $importTimeout = 180
    if (-not [int]::TryParse($waitRaw, [ref]$importTimeout)) {
        Write-Log -Message "AutopilotImportTimeoutSeconds ('$waitRaw') is not a number -- using 180." -Level WARN
        $importTimeout = 180
    }

    # ---- Hardware ----------------------------------------------------------
    Write-Log -Message 'Reading device hardware information...'
    $hardware = Get-DeviceHardwareInfo
    $Script:Result.Serial = $hardware.SerialNumber
    Write-Log -Message "Serial: '$($hardware.SerialNumber)', Manufacturer: '$($hardware.Manufacturer)', Model: '$($hardware.Model)', hash length: $($hardware.HardwareHash.Length)."

    if (-not (Test-HardwareInfo -Info $hardware)) {
        $Script:Result.Status  = 'HardwareError'
        $Script:Result.Message = 'Serial number or hardware hash unavailable'
        return $Script:ExitHardwareError
    }

    # ---- Certificate + token ------------------------------------------------
    $certificate = $null
    try {
        $certificate = Get-CertificateFromBase64 -Base64 $certBase64 -Password $certPassword
        if (-not $certificate) {
            $Script:Result.Status  = 'CertError'
            $Script:Result.Message = 'Certificate could not be loaded'
            return $Script:ExitCertError
        }

        $token = Get-GraphAccessToken -Certificate $certificate `
                                      -TenantId $tenantId `
                                      -ClientId $appId `
                                      -LoginHost $loginHost `
                                      -GraphHost $graphHost
        if (-not $token) {
            $Script:Result.Status  = 'AuthError'
            $Script:Result.Message = 'Could not obtain a Graph access token'
            return $Script:ExitAuthError
        }

        # ---- Already registered? --------------------------------------------
        if ($skipExisting) {
            if (Test-AlreadyRegistered -SerialNumber $hardware.SerialNumber -AccessToken $token -GraphHost $graphHost) {
                Write-Log -Message 'Nothing to do -- this device is already in Autopilot. Set AutopilotSkipIfRegistered to false to re-import anyway.' -Level SUCCESS
                $Script:Result.Status  = 'AlreadyRegistered'
                $Script:Result.Message = 'Device was already registered in Autopilot'
                return $Script:ExitSuccess
            }
        }
        else {
            Write-Log -Message 'AutopilotSkipIfRegistered is false -- importing without checking for an existing registration.' -Level WARN
        }

        # ---- Import -----------------------------------------------------------
        $Script:Result.GroupTag = $groupTag
        if ($groupTag)     { Write-Log -Message "Group tag: '$groupTag'" }
        if ($assignedUser) { Write-Log -Message "Assigned user: '$assignedUser'" }

        $import = $null
        try {
            $import = Invoke-AutopilotImport -HardwareInfo $hardware `
                                             -AccessToken $token `
                                             -GraphHost $graphHost `
                                             -GroupTag $groupTag `
                                             -AssignedUser $assignedUser
        }
        catch {
            Write-Log -Message "The Autopilot import request failed: $($_.Exception.Message)" -Level ERROR
            Write-Log -Message 'HINT: if this is a 403, the app registration is missing DeviceManagementServiceConfig.ReadWrite.All or admin consent was never granted.' -Level ERROR
            $Script:Result.Status  = 'ImportFailed'
            $Script:Result.Message = $_.Exception.Message
            return $Script:ExitImportError
        }

        Write-Log -Message "Import accepted (import id $($import.id))." -Level SUCCESS

        # ---- Wait for the service to finish ------------------------------------
        $outcome = Wait-AutopilotImport -ImportId $import.id `
                                        -AccessToken $token `
                                        -GraphHost $graphHost `
                                        -TimeoutSeconds $importTimeout

        if ($outcome.Completed -and -not $outcome.Succeeded) {
            $Script:Result.Status  = 'ImportFailed'
            $Script:Result.Message = "Autopilot rejected the import: $($outcome.ErrorName)"
            return $Script:ExitImportError
        }

        if (-not $outcome.Completed) {
            # Submitted but unconfirmed. Not a failure -- the service usually finishes on its
            # own -- but the job should not claim success either.
            $Script:Result.Status  = 'SubmittedUnconfirmed'
            $Script:Result.Message = "Submitted, but the import had not completed after ${importTimeout}s"
            Write-Log -Message 'Treating this as a partial result. Verify in Intune before re-running.' -Level WARN
            return $Script:ExitPartial
        }

        Write-Log -Message 'Autopilot import completed.' -Level SUCCESS
        $Script:Result.Status  = 'Registered'
        $Script:Result.Message = 'Device registered with Autopilot'

        # ---- Optional device name ---------------------------------------------
        if (-not [string]::IsNullOrWhiteSpace($nameTemplate)) {
            $computerName = Expand-NameToken -Template $nameTemplate -HardwareInfo $hardware
            $Script:Result.ComputerName = $computerName

            if ([string]::IsNullOrWhiteSpace($outcome.DeviceRegistrationId)) {
                Write-Log -Message 'The import completed but returned no device registration id, so the name could not be set.' -Level WARN
                $Script:Result.Status  = 'RegisteredNameNotSet'
                $Script:Result.Message = 'Registered; device name could not be set'
                return $Script:ExitPartial
            }

            $named = Set-AutopilotDeviceName -DeviceRegistrationId $outcome.DeviceRegistrationId `
                                             -ComputerName $computerName `
                                             -AccessToken $token `
                                             -GraphHost $graphHost
            if (-not $named) {
                $Script:Result.Status  = 'RegisteredNameNotSet'
                $Script:Result.Message = 'Registered; device name could not be set'
                return $Script:ExitPartial
            }
        }

        Write-Log -Message 'Autopilot device sync in Intune can take a few minutes, so the device will not appear in the portal immediately.'
        return $Script:ExitSuccess
    }
    finally {
        # Always dispose the certificate -- this is what stops the private key being left
        # behind on the endpoint after the job finishes.
        if ($certificate) {
            try {
                $certificate.Dispose()
                Write-Log -Message 'Certificate disposed; the private key was not persisted to this device.' -Level DEBUG
            }
            catch {
                Write-Log -Message "Could not dispose the certificate: $($_.Exception.Message)" -Level DEBUG
            }
        }
    }
}

#endregion

$exitCode = $Script:ExitUnexpected
try {
    $exitCode = Invoke-Main
}
catch {
    Write-Log -Message "Unhandled error: $($_.Exception.Message)" -Level ERROR
    Write-Log -Message "At line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line -replace '\s+', ' ')" -Level ERROR
    $Script:Result.Status  = 'UnexpectedError'
    $Script:Result.Message = $_.Exception.Message
    $exitCode = $Script:ExitUnexpected
}
finally {
    $udfNumber = 0
    if ([int]::TryParse((Get-RmmVariable -Name 'AutopilotUdfNumber'), [ref]$udfNumber) -and $udfNumber -gt 0) {
        Set-DattoUdf -Number $udfNumber -Value ("Autopilot: {0} ({1})" -f $Script:Result.Status, (Get-Date).ToString('yyyy-MM-dd HH:mm'))
    }

    Write-Log -Message "Finished with status '$($Script:Result.Status)' (exit code $exitCode)."
    Write-DattoResult
}

exit $exitCode
