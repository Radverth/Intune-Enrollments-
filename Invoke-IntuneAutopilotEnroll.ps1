#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Menu-driven tool for enrolling a Windows endpoint into Windows Autopilot / Intune.

.DESCRIPTION
    Single-file console tool intended for MSP technicians provisioning machines one at a
    time. Authentication to Microsoft Graph is certificate-based against an Entra ID (Azure
    AD) app registration -- no client secrets are ever requested, generated, or stored.

    Configuration (TenantId / AppId / certificate thumbprint) is persisted to
    C:\ProgramData\AffinityIT\IntuneAutopilotEnroll\config.json so the tool only needs to be
    configured once per tenant. Every later machine just runs the enrollment option.

    All actions are logged with timestamps to
    C:\ProgramData\AffinityIT\IntuneAutopilotEnroll\enroll.log

.NOTES
    Requires elevation -- the tool reads and writes Cert:\LocalMachine\My.
    Compatible with Windows PowerShell 5.1 and PowerShell 7 on Windows.
#>

[CmdletBinding()]
param()

#region --------------------------------------------------------------- Constants

$Script:ToolName          = 'Intune Autopilot Enrollment Tool'
$Script:ToolVersion       = '1.0.0'
$Script:DataRoot          = 'C:\ProgramData\AffinityIT\IntuneAutopilotEnroll'
$Script:ConfigPath        = Join-Path $Script:DataRoot 'config.json'
$Script:LogPath           = Join-Path $Script:DataRoot 'enroll.log'
$Script:CertStore         = 'Cert:\LocalMachine\My'
$Script:CertFriendlyName  = 'AffinityIT Intune Autopilot Enroll'
$Script:GraphAppId        = '00000003-0000-0000-c000-000000000000'   # Microsoft Graph
$Script:AutopilotScript   = 'Get-WindowsAutopilotInfo'

# Graph modules the tool depends on. Installed on demand rather than failing.
$Script:RequiredModules = @(
    'Microsoft.Graph.Authentication'
    'Microsoft.Graph.Applications'
    'Microsoft.Graph.Identity.SignIns'
)

# Application (app-only) permissions the created app registration needs. Resolved by
# name against the Graph service principal's AppRoles at runtime -- role IDs are not
# hardcoded because they are not guaranteed to be stable across clouds/tenants.
$Script:RequiredGraphRoles = @(
    [pscustomobject]@{ Name = 'DeviceManagementServiceConfig.ReadWrite.All';   Optional = $false; Purpose = 'Register devices with the Autopilot service' }
    [pscustomobject]@{ Name = 'DeviceManagementManagedDevices.ReadWrite.All';  Optional = $false; Purpose = 'Read/write Intune managed device records' }
    [pscustomobject]@{ Name = 'Device.ReadWrite.All';                          Optional = $false; Purpose = 'Create/update the Entra ID device object' }
    [pscustomobject]@{ Name = 'GroupMember.ReadWrite.All';                     Optional = $true;  Purpose = 'Group tag / dynamic group flows (optional)' }
)

# Delegated scopes needed for the interactive sign-in used to create an app registration.
$Script:AppCreationScopes = @(
    'Application.ReadWrite.All'
    'AppRoleAssignment.ReadWrite.All'
    'Directory.Read.All'
)

#endregion

#region --------------------------------------------------------------- Logging

function Initialize-DataStore {
    <#
        Ensures the ProgramData folder exists before anything tries to log or save config.
        Deliberately quiet on success -- this runs before logging is usable.
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-Path -LiteralPath $Script:DataRoot)) {
        try {
            $null = New-Item -Path $Script:DataRoot -ItemType Directory -Force -ErrorAction Stop
        }
        catch {
            Write-Host "FATAL: unable to create '$Script:DataRoot': $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }
}

function Write-Log {
    <#
        Timestamped append to enroll.log, with an optional coloured console echo.
        Every action in the tool goes through here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowEmptyString()]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'DEBUG')]
        [string]$Level = 'INFO',

        # Suppress the console echo (file only) -- used for noisy diagnostic detail.
        [switch]$NoConsole
    )

    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line  = '{0} [{1,-7}] {2}' -f $stamp, $Level, $Message

    try {
        Add-Content -LiteralPath $Script:LogPath -Value $line -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        # Never let a logging failure take down the tool.
        Write-Host "(log write failed: $($_.Exception.Message))" -ForegroundColor DarkGray
    }

    if ($NoConsole -or $Level -eq 'DEBUG') { return }

    $colour = switch ($Level) {
        'ERROR'   { 'Red' }
        'WARN'    { 'Yellow' }
        'SUCCESS' { 'Green' }
        default   { 'Gray' }
    }
    Write-Host $Message -ForegroundColor $colour
}

function Write-ErrorRecordToLog {
    <#
        Writes a friendly one-liner to the console and the full exception detail to the log.
        Keeps raw .NET stack traces out of the technician's face.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [string]$Context = 'Operation failed'
    )

    Write-Log -Message ("{0}: {1}" -f $Context, $ErrorRecord.Exception.Message) -Level ERROR

    $detail = @(
        "Exception type : $($ErrorRecord.Exception.GetType().FullName)"
        "Category       : $($ErrorRecord.CategoryInfo.Category)"
        "Target         : $($ErrorRecord.CategoryInfo.TargetName)"
        "Script line    : $($ErrorRecord.InvocationInfo.ScriptLineNumber)"
        "Position       : $($ErrorRecord.InvocationInfo.Line -replace '\s+', ' ')"
    ) -join ' | '
    Write-Log -Message $detail -Level DEBUG
}

#endregion

#region --------------------------------------------------------------- Console helpers

function Write-Header {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text)

    Write-Host ''
    Write-Host ('=' * 68) -ForegroundColor DarkCyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ('=' * 68) -ForegroundColor DarkCyan
    Write-Host ''
}

function Read-NonEmpty {
    <#
        Prompt that keeps asking until it gets a non-blank answer, unless -AllowBlank is
        set (in which case blank returns an empty string and means "skip this").
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [switch]$AllowBlank,
        [scriptblock]$Validator,
        [string]$ValidationMessage = 'That value does not look right, try again.'
    )

    while ($true) {
        $value = (Read-Host -Prompt $Prompt)
        if ($null -eq $value) { $value = '' }
        $value = $value.Trim()

        if ([string]::IsNullOrWhiteSpace($value)) {
            if ($AllowBlank) { return '' }
            Write-Host 'A value is required.' -ForegroundColor Yellow
            continue
        }

        if ($Validator -and -not (& $Validator $value)) {
            Write-Host $ValidationMessage -ForegroundColor Yellow
            continue
        }

        return $value
    }
}

function Confirm-Action {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [switch]$DefaultYes
    )

    $suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
    $answer = (Read-Host -Prompt "$Prompt $suffix")
    if ([string]::IsNullOrWhiteSpace($answer)) { return [bool]$DefaultYes }
    return ($answer.Trim() -match '^(y|yes)$')
}

function Pause-ForTech {
    [CmdletBinding()]
    param([string]$Message = 'Press Enter to return to the menu')
    Write-Host ''
    $null = Read-Host -Prompt $Message
}

function Test-GuidString {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $parsed = [guid]::Empty
    return [guid]::TryParse($Value, [ref]$parsed)
}

function Test-ThumbprintString {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $clean = ($Value -replace '[\s:]', '')
    return ($clean -match '^[0-9A-Fa-f]{40}$')
}

function Format-Thumbprint {
    # Normalises user-pasted thumbprints (certmgr copies include spaces and an invisible
    # left-to-right mark) into the bare uppercase hex the cert provider expects.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    return (($Value -replace '[^0-9A-Fa-f]', '')).ToUpperInvariant()
}

#endregion

#region --------------------------------------------------------------- Configuration

function Get-ToolConfig {
    <#
        Reads config.json. Returns $null when there is no usable config rather than
        throwing -- callers decide whether a missing config is fatal.
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-Path -LiteralPath $Script:ConfigPath)) { return $null }

    try {
        $raw = Get-Content -LiteralPath $Script:ConfigPath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        $config = $raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-ErrorRecordToLog -ErrorRecord $_ -Context "Could not read config from '$Script:ConfigPath'"
        return $null
    }

    foreach ($required in @('TenantId', 'AppId', 'CertificateThumbprint')) {
        if ([string]::IsNullOrWhiteSpace($config.$required)) {
            Write-Log -Message "Config file is missing '$required' -- treating it as unconfigured." -Level WARN
            return $null
        }
    }

    return $config
}

function Save-ToolConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$AppId,
        [Parameter(Mandatory)][string]$CertificateThumbprint,
        [string]$AppDisplayName = '',
        [string]$AppObjectId = '',
        [string]$ServicePrincipalId = '',
        [string]$Source = 'Manual'
    )

    $config = [ordered]@{
        TenantId              = $TenantId
        AppId                 = $AppId
        AppDisplayName        = $AppDisplayName
        AppObjectId           = $AppObjectId
        ServicePrincipalId    = $ServicePrincipalId
        CertificateThumbprint = (Format-Thumbprint $CertificateThumbprint)
        Source                = $Source
        SavedOn               = (Get-Date).ToString('o')
        SavedBy               = "$env:USERDOMAIN\$env:USERNAME"
        SavedFrom             = $env:COMPUTERNAME
        ToolVersion           = $Script:ToolVersion
    }

    try {
        Initialize-DataStore
        ($config | ConvertTo-Json -Depth 4) |
            Set-Content -LiteralPath $Script:ConfigPath -Encoding UTF8 -ErrorAction Stop

        Write-Log -Message "Configuration saved to $Script:ConfigPath" -Level SUCCESS
        return $true
    }
    catch {
        Write-ErrorRecordToLog -ErrorRecord $_ -Context 'Failed to save configuration'
        return $false
    }
}

#endregion

#region --------------------------------------------------------------- Dependencies

function Initialize-PSGalleryAccess {
    <#
        Windows PowerShell 5.1 defaults to TLS 1.0/1.1, which the PowerShell Gallery has
        not accepted for years. Also makes sure the NuGet provider exists so Install-Module
        doesn't stop for an interactive prompt mid-run.
    #>
    [CmdletBinding()]
    param()

    try {
        if ([Net.ServicePointManager]::SecurityProtocol -notmatch 'Tls12') {
            [Net.ServicePointManager]::SecurityProtocol =
                [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Write-Log -Message 'Enabled TLS 1.2 for this session.' -Level DEBUG
        }
    }
    catch {
        Write-Log -Message "Could not force TLS 1.2: $($_.Exception.Message)" -Level DEBUG
    }

    try {
        $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
        if (-not $nuget -or $nuget.Version -lt [version]'2.8.5.201') {
            Write-Log -Message 'Installing the NuGet package provider...'
            $null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers -ErrorAction Stop
        }
    }
    catch {
        Write-Log -Message "NuGet provider bootstrap failed (continuing): $($_.Exception.Message)" -Level WARN
    }
}

function Install-RequiredModule {
    <#
        Imports a module, installing it from the PowerShell Gallery first if it is absent.
        Returns $true only when the module is importable afterwards.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    if (Get-Module -Name $Name) { return $true }

    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Log -Message "Module '$Name' is not installed. Installing from the PowerShell Gallery (this can take a few minutes)..."
        Initialize-PSGalleryAccess
        try {
            Install-Module -Name $Name -Scope AllUsers -Force -AllowClobber -Repository PSGallery -ErrorAction Stop
            Write-Log -Message "Installed module '$Name'." -Level SUCCESS
        }
        catch {
            Write-ErrorRecordToLog -ErrorRecord $_ -Context "Failed to install module '$Name'"
            Write-Log -Message "Install it manually with: Install-Module $Name -Scope AllUsers" -Level WARN
            return $false
        }
    }

    try {
        Import-Module -Name $Name -ErrorAction Stop
        Write-Log -Message "Imported module '$Name'." -Level DEBUG
        return $true
    }
    catch {
        Write-ErrorRecordToLog -ErrorRecord $_ -Context "Failed to import module '$Name'"
        return $false
    }
}

function Initialize-GraphModules {
    <#
        Ensures every Graph module the tool needs is present. Called lazily by the menu
        actions that actually talk to Graph so that, say, viewing config stays instant.
    #>
    [CmdletBinding()]
    param([string[]]$Modules = $Script:RequiredModules)

    $allOk = $true
    foreach ($module in $Modules) {
        if (-not (Install-RequiredModule -Name $module)) { $allOk = $false }
    }

    if (-not $allOk) {
        Write-Log -Message 'One or more required Graph modules are unavailable -- this action cannot continue.' -Level ERROR
    }
    return $allOk
}

function Disconnect-GraphQuietly {
    # Disconnect-MgGraph throws when there is no active context; nobody needs to see that.
    [CmdletBinding()]
    param()

    try {
        if (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue) {
            if (Get-MgContext -ErrorAction SilentlyContinue) {
                $null = Disconnect-MgGraph -ErrorAction Stop
                Write-Log -Message 'Disconnected from Microsoft Graph.' -Level DEBUG
            }
        }
    }
    catch {
        Write-Log -Message "Disconnect from Graph reported: $($_.Exception.Message)" -Level DEBUG
    }
}

#endregion

#region --------------------------------------------------------------- Certificates

function Get-CandidateCertificate {
    <#
        Every cert in Cert:\LocalMachine\My that has a usable private key -- i.e. everything
        that could plausibly be used for app-only Graph auth.
    #>
    [CmdletBinding()]
    param()

    try {
        $certs = @(Get-ChildItem -Path $Script:CertStore -ErrorAction Stop |
                        Where-Object { $_.HasPrivateKey })
        return $certs | Sort-Object NotAfter -Descending
    }
    catch {
        Write-ErrorRecordToLog -ErrorRecord $_ -Context "Could not read $Script:CertStore"
        return @()
    }
}

function Get-CertificateByThumbprint {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Thumbprint)

    $clean = Format-Thumbprint $Thumbprint
    if ([string]::IsNullOrWhiteSpace($clean)) { return $null }

    try {
        return Get-Item -Path (Join-Path $Script:CertStore $clean) -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function Show-CertificateTable {
    <#
        Numbered listing of candidate certs. Returns the array it printed so the caller can
        index straight into it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Certificates
    )

    if (-not $Certificates -or $Certificates.Count -eq 0) {
        Write-Host 'No certificates with a private key were found in Cert:\LocalMachine\My.' -ForegroundColor Yellow
        return @()
    }

    $now = Get-Date
    Write-Host ''
    Write-Host ('  {0,-3} {1,-40} {2,-42} {3,-12} {4}' -f '#', 'Subject', 'Thumbprint', 'Expires', 'Notes') -ForegroundColor White
    Write-Host ('  ' + ('-' * 118)) -ForegroundColor DarkGray

    for ($i = 0; $i -lt $Certificates.Count; $i++) {
        $cert    = $Certificates[$i]
        $subject = if ($cert.Subject.Length -gt 39) { $cert.Subject.Substring(0, 36) + '...' } else { $cert.Subject }

        $notes = @()
        if ($cert.NotAfter -lt $now)             { $notes += 'EXPIRED' }
        elseif ($cert.NotAfter -lt $now.AddDays(30)) { $notes += 'expires soon' }
        if ($cert.NotBefore -gt $now)            { $notes += 'not yet valid' }
        if ($cert.FriendlyName -eq $Script:CertFriendlyName) { $notes += 'tool-created' }
        if (-not $cert.HasPrivateKey)            { $notes += 'NO PRIVATE KEY' }

        $colour = if ($cert.NotAfter -lt $now) { 'DarkGray' }
                  elseif ($cert.FriendlyName -eq $Script:CertFriendlyName) { 'Green' }
                  else { 'Gray' }

        Write-Host ('  {0,-3} {1,-40} {2,-42} {3,-12} {4}' -f `
            ($i + 1), $subject, $cert.Thumbprint, $cert.NotAfter.ToString('yyyy-MM-dd'), ($notes -join ', ')) -ForegroundColor $colour
    }
    Write-Host ''

    return $Certificates
}

function Select-CertificateThumbprint {
    <#
        Numbered pick list over the local machine store, with a manual-entry escape hatch.
        Returns a bare thumbprint string, or $null if the tech backed out.
    #>
    [CmdletBinding()]
    param()

    $certs = @(Get-CandidateCertificate)
    $null  = Show-CertificateTable -Certificates $certs

    Write-Host '  Enter a number to pick a certificate from the list above,'
    Write-Host '  or paste a thumbprint directly, or press Enter to cancel.'
    Write-Host ''

    while ($true) {
        $answer = Read-Host -Prompt 'Certificate'
        if ([string]::IsNullOrWhiteSpace($answer)) { return $null }
        $answer = $answer.Trim()

        # Numbered selection
        if ($answer -match '^\d+$' -and $certs.Count -gt 0) {
            $index = [int]$answer - 1
            if ($index -ge 0 -and $index -lt $certs.Count) {
                $chosen = $certs[$index]
                Write-Log -Message "Selected certificate $($chosen.Thumbprint) ($($chosen.Subject))."
                return $chosen.Thumbprint
            }
            Write-Host "Pick a number between 1 and $($certs.Count)." -ForegroundColor Yellow
            continue
        }

        # Manual thumbprint entry
        if (Test-ThumbprintString $answer) {
            $clean = Format-Thumbprint $answer
            $found = Get-CertificateByThumbprint -Thumbprint $clean
            if (-not $found) {
                Write-Host "No certificate with thumbprint $clean exists in $Script:CertStore." -ForegroundColor Yellow
                if (-not (Confirm-Action -Prompt 'Use it anyway?')) { continue }
            }
            elseif (-not $found.HasPrivateKey) {
                Write-Host 'That certificate has no private key -- app-only auth will fail with it.' -ForegroundColor Yellow
                if (-not (Confirm-Action -Prompt 'Use it anyway?')) { continue }
            }
            return $clean
        }

        Write-Host 'Enter a list number, or a 40-character hex thumbprint.' -ForegroundColor Yellow
    }
}

function New-EnrollmentCertificate {
    <#
        Self-signed 2048-bit RSA / SHA256 cert with a 2-year life, created directly in
        Cert:\LocalMachine\My and tagged with the tool's friendly name so option 5 can
        tell tool-created certs apart from whatever else is in the store.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Subject
    )

    try {
        Write-Log -Message "Creating a self-signed certificate (CN=$Subject, RSA 2048, SHA256, 2-year expiry)..."

        $params = @{
            Subject           = "CN=$Subject"
            CertStoreLocation = $Script:CertStore
            KeyAlgorithm      = 'RSA'
            KeyLength         = 2048
            HashAlgorithm     = 'SHA256'
            KeyExportPolicy   = 'Exportable'
            KeySpec           = 'Signature'
            KeyUsage          = 'DigitalSignature'
            NotBefore         = (Get-Date).AddMinutes(-10)   # tolerate small clock skew
            NotAfter          = (Get-Date).AddYears(2)
            FriendlyName      = $Script:CertFriendlyName
            Provider          = 'Microsoft Enhanced RSA and AES Cryptographic Provider'
            ErrorAction       = 'Stop'
        }

        $cert = New-SelfSignedCertificate @params

        Write-Log -Message "Created certificate $($cert.Thumbprint), valid until $($cert.NotAfter.ToString('yyyy-MM-dd'))." -Level SUCCESS
        return $cert
    }
    catch {
        Write-ErrorRecordToLog -ErrorRecord $_ -Context 'Certificate creation failed'
        return $null
    }
}

function Test-ConfiguredCertificate {
    <#
        Shared health check for a configured thumbprint. Returns a small status object so
        both "view config" and "enroll" can report the same way.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Thumbprint)

    $status = [pscustomobject]@{
        Thumbprint    = (Format-Thumbprint $Thumbprint)
        Present       = $false
        HasPrivateKey = $false
        Expired       = $false
        NotYetValid   = $false
        NotAfter      = $null
        Subject       = ''
        IsUsable      = $false
        Summary       = 'Not present on this machine'
    }

    $cert = Get-CertificateByThumbprint -Thumbprint $status.Thumbprint
    if (-not $cert) { return $status }

    $now = Get-Date
    $status.Present       = $true
    $status.HasPrivateKey = $cert.HasPrivateKey
    $status.Expired       = ($cert.NotAfter -lt $now)
    $status.NotYetValid   = ($cert.NotBefore -gt $now)
    $status.NotAfter      = $cert.NotAfter
    $status.Subject       = $cert.Subject
    $status.IsUsable      = ($cert.HasPrivateKey -and -not $status.Expired -and -not $status.NotYetValid)

    $status.Summary = if (-not $cert.HasPrivateKey)  { 'Present but the private key is missing' }
                      elseif ($status.Expired)       { "EXPIRED on $($cert.NotAfter.ToString('yyyy-MM-dd'))" }
                      elseif ($status.NotYetValid)   { "Not valid until $($cert.NotBefore.ToString('yyyy-MM-dd'))" }
                      else                           { "Valid until $($cert.NotAfter.ToString('yyyy-MM-dd'))" }

    return $status
}

#endregion

#region --------------------------------------------------------------- Graph connection

function Test-GraphCertificateConnection {
    <#
        Live connection test using app-only certificate auth. Connecting alone is not proof
        the credential works end to end, so this also issues a real read against the tenant
        before declaring success.

        Returns an object with Success plus, on success, the resolved tenant display name.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$AppId,
        [Parameter(Mandatory)][string]$CertificateThumbprint
    )

    $result = [pscustomobject]@{
        Success        = $false
        TenantName     = ''
        AppDisplayName = ''
        Message        = ''
    }

    Disconnect-GraphQuietly

    try {
        Write-Log -Message "Testing app-only connection to tenant $TenantId as app $AppId..."
        Connect-MgGraph -ClientId $AppId -TenantId $TenantId -CertificateThumbprint (Format-Thumbprint $CertificateThumbprint) -NoWelcome -ErrorAction Stop | Out-Null
    }
    catch {
        $result.Message = $_.Exception.Message
        Write-ErrorRecordToLog -ErrorRecord $_ -Context 'Connect-MgGraph failed'
        Show-ConnectionFailureHints -Message $result.Message
        Disconnect-GraphQuietly
        return $result
    }

    # A token in hand is not the same as a token that works. Make a real call.
    try {
        $org = Invoke-MgGraphRequest -Method GET -Uri 'v1.0/organization?$select=displayName,id' -ErrorAction Stop
        $result.TenantName = @($org.value)[0].displayName
        $result.Success    = $true
        Write-Log -Message "Connection verified against tenant '$($result.TenantName)'." -Level SUCCESS
    }
    catch {
        $result.Message = $_.Exception.Message
        Write-ErrorRecordToLog -ErrorRecord $_ -Context 'Connected, but the first Graph call failed'
        Show-ConnectionFailureHints -Message $result.Message
        Disconnect-GraphQuietly
        return $result
    }

    # Best effort: put a human-readable name against the app registration. The app-only
    # credential may not hold Application.Read.All, so a failure here is not an error.
    try {
        $apps = Invoke-MgGraphRequest -Method GET -Uri ("v1.0/applications?`$filter=appId eq '{0}'&`$select=displayName" -f $AppId) -ErrorAction Stop
        $result.AppDisplayName = @($apps.value)[0].displayName
    }
    catch {
        Write-Log -Message "Could not read the app registration's display name (needs Application.Read.All): $($_.Exception.Message)" -Level DEBUG
    }

    Disconnect-GraphQuietly
    return $result
}

function Show-ConnectionFailureHints {
    <#
        Turns the usual opaque Graph/MSAL errors into the three things that are actually
        wrong 95% of the time.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Message)

    Write-Host ''
    Write-Host '  Connection test FAILED. The usual causes, in order of likelihood:' -ForegroundColor Yellow
    Write-Host '    1. The certificate public key has not been uploaded to the app registration' -ForegroundColor Yellow
    Write-Host '       (Entra ID > App registrations > your app > Certificates & secrets).' -ForegroundColor Yellow
    Write-Host '    2. The app has the Graph application permissions but admin consent was' -ForegroundColor Yellow
    Write-Host '       never granted (Entra ID > App registrations > your app > API permissions).' -ForegroundColor Yellow
    Write-Host '    3. The certificate in Cert:\LocalMachine\My has no private key, has expired,' -ForegroundColor Yellow
    Write-Host '       or the account running this tool cannot read the key.' -ForegroundColor Yellow

    switch -Regex ($Message) {
        'AADSTS700027|AADSTS700016|Invalid client secret|client assertion' {
            Write-Host '    -> The error text points at cause 1 (certificate/app mismatch).' -ForegroundColor Yellow
        }
        'AADSTS65001|Authorization_RequestDenied|Insufficient privileges|Forbidden|403' {
            Write-Host '    -> The error text points at cause 2 (missing consent or permissions).' -ForegroundColor Yellow
        }
        'private key|Keyset does not exist|CryptographicException' {
            Write-Host '    -> The error text points at cause 3 (private key problem).' -ForegroundColor Yellow
        }
        'AADSTS90002|tenant.*not found' {
            Write-Host '    -> The tenant ID does not resolve. Double-check it.' -ForegroundColor Yellow
        }
    }
    Write-Host ''
}

#endregion

#region --------------------------------------------------------------- Menu 1: connect existing

function Invoke-ConnectExistingApp {
    <#
        Menu option 1. Collects tenant/app/cert, proves the combination works against the
        live tenant, and only then writes it to config.json.
    #>
    [CmdletBinding()]
    param()

    Write-Header 'Connect to an existing app registration'
    Write-Log -Message 'Menu 1 selected: connect to an existing app registration.' -Level DEBUG

    if (-not (Initialize-GraphModules -Modules @('Microsoft.Graph.Authentication'))) {
        Pause-ForTech
        return
    }

    $existing = Get-ToolConfig
    if ($existing) {
        Write-Host "  A configuration already exists for tenant $($existing.TenantId) / app $($existing.AppId)." -ForegroundColor DarkGray
        Write-Host '  Completing this option will overwrite it.' -ForegroundColor DarkGray
        Write-Host ''
    }

    $tenantId = Read-NonEmpty -Prompt 'Tenant ID (GUID)' `
                              -Validator { param($v) Test-GuidString $v } `
                              -ValidationMessage 'Tenant ID must be a GUID, e.g. 00000000-1111-2222-3333-444444444444.'

    $appId = Read-NonEmpty -Prompt 'Application (Client) ID (GUID)' `
                           -Validator { param($v) Test-GuidString $v } `
                           -ValidationMessage 'App ID must be a GUID.'

    Write-Host ''
    Write-Host '  Select the certificate this app registration authenticates with:' -ForegroundColor White
    $thumbprint = Select-CertificateThumbprint
    if (-not $thumbprint) {
        Write-Log -Message 'Certificate selection cancelled -- nothing was saved.' -Level WARN
        Pause-ForTech
        return
    }

    Write-Host ''
    $test = Test-GraphCertificateConnection -TenantId $tenantId -AppId $appId -CertificateThumbprint $thumbprint

    if (-not $test.Success) {
        Write-Log -Message 'Connection test failed -- configuration was NOT saved.' -Level ERROR
        Pause-ForTech
        return
    }

    Write-Host ''
    Write-Host "  Connected successfully to: $($test.TenantName)" -ForegroundColor Green
    if ($test.AppDisplayName) {
        Write-Host "  App registration        : $($test.AppDisplayName)" -ForegroundColor Green
    }
    Write-Host ''

    $saved = Save-ToolConfig -TenantId $tenantId `
                             -AppId $appId `
                             -CertificateThumbprint $thumbprint `
                             -AppDisplayName $test.AppDisplayName `
                             -Source 'ConnectedToExistingApp'

    if ($saved) {
        Write-Log -Message 'This machine is now configured. Option 3 will enroll devices with it.' -Level SUCCESS
    }

    Pause-ForTech
}

#endregion

#region --------------------------------------------------------------- Menu 2: create new app

function Resolve-GraphAppRole {
    <#
        Maps permission names to the Graph service principal's AppRole IDs. Resolving by
        name matters -- app role GUIDs are not guaranteed to match across clouds, and
        hardcoding them is the classic way this kind of tool breaks in GCC/sovereign
        tenants.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$GraphServicePrincipal,
        [Parameter(Mandatory)][object[]]$RequiredRoles
    )

    $resolved = @()

    foreach ($required in $RequiredRoles) {
        $role = $GraphServicePrincipal.AppRoles |
                    Where-Object { $_.Value -eq $required.Name -and $_.AllowedMemberTypes -contains 'Application' } |
                    Select-Object -First 1

        if ($role) {
            Write-Log -Message "Resolved '$($required.Name)' to app role $($role.Id)." -Level DEBUG
            $resolved += [pscustomobject]@{
                Name     = $required.Name
                Id       = $role.Id
                Optional = $required.Optional
                Purpose  = $required.Purpose
            }
        }
        elseif ($required.Optional) {
            Write-Log -Message "Optional permission '$($required.Name)' could not be resolved in this tenant -- skipping it." -Level WARN
        }
        else {
            Write-Log -Message "Required permission '$($required.Name)' could not be resolved against the Graph service principal." -Level ERROR
        }
    }

    return $resolved
}

function Grant-AppRoleConsent {
    <#
        Assigns each resolved app role to the new service principal, which is what "grant
        admin consent" does under the covers. Needs Global Administrator or Privileged Role
        Administrator; when the signed-in tech is neither, this must not crash the tool --
        it reports the manual fallback and moves on.

        Returns a summary object of granted / already-present / failed role names.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ClientServicePrincipalId,
        [Parameter(Mandatory)][string]$GraphServicePrincipalId,
        [Parameter(Mandatory)][object[]]$Roles
    )

    $summary = [pscustomobject]@{
        Granted = @()
        Skipped = @()
        Failed  = @()
    }

    foreach ($role in $Roles) {
        try {
            $body = @{
                principalId = $ClientServicePrincipalId
                resourceId  = $GraphServicePrincipalId
                appRoleId   = $role.Id
            }

            $null = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ClientServicePrincipalId `
                                                            -BodyParameter $body `
                                                            -ErrorAction Stop

            $summary.Granted += $role.Name
            Write-Log -Message "  Consent granted: $($role.Name)" -Level SUCCESS
        }
        catch {
            # A duplicate assignment is a success from the technician's point of view.
            if ($_.Exception.Message -match 'already exists|Permission being assigned was already assigned') {
                $summary.Skipped += $role.Name
                Write-Log -Message "  Already granted: $($role.Name)" -Level INFO
                continue
            }

            $summary.Failed += $role.Name
            Write-Log -Message "  Could not grant: $($role.Name) -- $($_.Exception.Message)" -Level WARN
            Write-ErrorRecordToLog -ErrorRecord $_ -Context "Consent grant failed for $($role.Name)"
        }
    }

    return $summary
}

function Invoke-CreateNewApp {
    <#
        Menu option 2. Interactive sign-in, self-signed cert, app registration using that
        cert as its only credential, service principal, then a best-effort admin consent.
    #>
    [CmdletBinding()]
    param()

    Write-Header 'Create a new app registration'
    Write-Log -Message 'Menu 2 selected: create a new app registration.' -Level DEBUG

    if (-not (Initialize-GraphModules)) {
        Pause-ForTech
        return
    }

    Write-Host '  This will:' -ForegroundColor White
    Write-Host '    - sign you in interactively (you need an admin account in the target tenant)'
    Write-Host '    - create a self-signed certificate in Cert:\LocalMachine\My'
    Write-Host '    - create an app registration using that certificate as its only credential'
    Write-Host '    - request admin consent for the Graph permissions Autopilot enrollment needs'
    Write-Host ''
    Write-Host '  No client secret is created or stored at any point.' -ForegroundColor DarkGray
    Write-Host ''

    if (-not (Confirm-Action -Prompt 'Continue?' -DefaultYes)) {
        Write-Log -Message 'App registration creation cancelled by the technician.' -Level WARN
        return
    }

    $defaultName = 'AffinityIT Intune Autopilot Enrollment'
    $displayName = Read-NonEmpty -Prompt "App registration display name [$defaultName]" -AllowBlank
    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $defaultName }

    # ---- Interactive sign-in -------------------------------------------------
    Disconnect-GraphQuietly
    try {
        Write-Host ''
        Write-Log -Message "Opening an interactive sign-in for scopes: $($Script:AppCreationScopes -join ', ')"
        Connect-MgGraph -Scopes $Script:AppCreationScopes -NoWelcome -ErrorAction Stop | Out-Null

        $context = Get-MgContext -ErrorAction Stop
        $tenantId = $context.TenantId
        Write-Log -Message "Signed in as $($context.Account) against tenant $tenantId." -Level SUCCESS
    }
    catch {
        Write-ErrorRecordToLog -ErrorRecord $_ -Context 'Interactive sign-in failed'
        Write-Log -Message 'Cannot create an app registration without a successful sign-in.' -Level ERROR
        Disconnect-GraphQuietly
        Pause-ForTech
        return
    }

    $certificate = $null
    try {
        # ---- Resolve permissions against the Graph SP ------------------------
        Write-Host ''
        Write-Log -Message 'Resolving Graph application permissions by name...'
        $graphSp = Get-MgServicePrincipal -Filter "appId eq '$Script:GraphAppId'" -ErrorAction Stop | Select-Object -First 1
        if (-not $graphSp) { throw "The Microsoft Graph service principal ($Script:GraphAppId) was not found in this tenant." }

        $roles = @(Resolve-GraphAppRole -GraphServicePrincipal $graphSp -RequiredRoles $Script:RequiredGraphRoles)

        $missingRequired = @($Script:RequiredGraphRoles |
                                Where-Object { -not $_.Optional -and $roles.Name -notcontains $_.Name })
        if ($missingRequired.Count -gt 0) {
            throw ("These required permissions could not be resolved: {0}" -f (($missingRequired.Name) -join ', '))
        }

        Write-Log -Message "Resolved $($roles.Count) application permission(s)." -Level SUCCESS

        # ---- Certificate ------------------------------------------------------
        Write-Host ''
        $certSubject = "$displayName ($env:COMPUTERNAME)"
        $certificate = New-EnrollmentCertificate -Subject $certSubject
        if (-not $certificate) { throw 'Certificate creation failed -- the app registration was not created.' }

        # ---- App registration -------------------------------------------------
        Write-Host ''
        Write-Log -Message "Creating app registration '$displayName'..."

        $keyCredential = @{
            Type        = 'AsymmetricX509Cert'
            Usage       = 'Verify'
            Key         = $certificate.RawData
            DisplayName = "CN=$certSubject"
            StartDateTime = $certificate.NotBefore
            EndDateTime   = $certificate.NotAfter
        }

        $requiredResourceAccess = @{
            ResourceAppId  = $Script:GraphAppId
            ResourceAccess = @($roles | ForEach-Object { @{ Id = $_.Id; Type = 'Role' } })
        }

        $app = New-MgApplication -DisplayName $displayName `
                                 -SignInAudience 'AzureADMyOrg' `
                                 -KeyCredentials @($keyCredential) `
                                 -RequiredResourceAccess @($requiredResourceAccess) `
                                 -Notes 'Created by the AffinityIT Intune Autopilot Enrollment tool. Certificate auth only.' `
                                 -ErrorAction Stop

        Write-Log -Message "Created app registration '$displayName' (AppId $($app.AppId))." -Level SUCCESS

        # ---- Service principal ------------------------------------------------
        # Directory replication means the app is not always visible to the SP endpoint the
        # instant it is created; retry briefly rather than failing the whole run.
        Write-Host ''
        Write-Log -Message 'Creating the service principal...'
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
                Write-Log -Message "  Service principal not ready yet (attempt $attempt/6), waiting for directory replication..." -Level DEBUG
                Start-Sleep -Seconds 5
            }
        }
        if (-not $clientSp) { throw 'The service principal could not be created.' }
        Write-Log -Message "Created service principal $($clientSp.Id)." -Level SUCCESS

        # ---- Admin consent (best effort) --------------------------------------
        Write-Host ''
        Write-Log -Message 'Attempting to grant admin consent for the application permissions...'
        $consent = Grant-AppRoleConsent -ClientServicePrincipalId $clientSp.Id `
                                        -GraphServicePrincipalId $graphSp.Id `
                                        -Roles $roles

        if ($consent.Failed.Count -gt 0) {
            Write-Host ''
            Write-Log -Message 'Admin consent could not be granted automatically for: ' -Level WARN
            foreach ($name in $consent.Failed) { Write-Host "      - $name" -ForegroundColor Yellow }
            Write-Host ''
            Write-Host '  This normally means the signed-in account is not a Global Administrator' -ForegroundColor Yellow
            Write-Host '  or Privileged Role Administrator. The app registration itself was created' -ForegroundColor Yellow
            Write-Host '  successfully -- grant consent manually:' -ForegroundColor Yellow
            Write-Host ''
            Write-Host '    Entra ID > App registrations > ' -NoNewline -ForegroundColor Yellow
            Write-Host $displayName -ForegroundColor White -NoNewline
            Write-Host ' > API permissions' -ForegroundColor Yellow
            Write-Host '    then click "Grant admin consent for <tenant>".' -ForegroundColor Yellow
            Write-Host ''
        }
        else {
            Write-Log -Message 'Admin consent granted for all requested permissions.' -Level SUCCESS
        }

        # ---- Persist ----------------------------------------------------------
        $saved = Save-ToolConfig -TenantId $tenantId `
                                 -AppId $app.AppId `
                                 -CertificateThumbprint $certificate.Thumbprint `
                                 -AppDisplayName $displayName `
                                 -AppObjectId $app.Id `
                                 -ServicePrincipalId $clientSp.Id `
                                 -Source 'CreatedNewApp'

        Write-Host ''
        Write-Host '  Summary' -ForegroundColor White
        Write-Host "    Tenant ID   : $tenantId"
        Write-Host "    App name    : $displayName"
        Write-Host "    App ID      : $($app.AppId)"
        Write-Host "    Certificate : $($certificate.Thumbprint)"
        Write-Host "    Expires     : $($certificate.NotAfter.ToString('yyyy-MM-dd'))"
        Write-Host ''

        if ($saved -and $consent.Failed.Count -eq 0) {
            Write-Host '  Note: new app role assignments can take a minute or two to take effect.' -ForegroundColor DarkGray
            Write-Host '  If option 3 fails immediately after this, wait a moment and retry.' -ForegroundColor DarkGray
            Write-Host ''
        }
    }
    catch {
        Write-ErrorRecordToLog -ErrorRecord $_ -Context 'App registration setup failed'

        if ($certificate) {
            Write-Log -Message "The certificate $($certificate.Thumbprint) was created before the failure and is still in $Script:CertStore." -Level WARN
            Write-Log -Message 'Use menu option 5 to remove it if you do not need it.' -Level WARN
        }
    }
    finally {
        Disconnect-GraphQuietly
    }

    Pause-ForTech
}

#endregion

#region --------------------------------------------------------------- Menu 3: enroll device

function Get-AutopilotInfoScript {
    <#
        Get-WindowsAutopilotInfo ships on the PowerShell Gallery as a *script*, not a
        module, so it is handled with Install-Script / Get-InstalledScript. Installs it if
        missing and returns the full path to the .ps1, or $null.
    #>
    [CmdletBinding()]
    param()

    $resolve = {
        $installed = Get-InstalledScript -Name $Script:AutopilotScript -ErrorAction SilentlyContinue
        if ($installed -and $installed.InstalledLocation) {
            $candidate = Join-Path $installed.InstalledLocation "$Script:AutopilotScript.ps1"
            if (Test-Path -LiteralPath $candidate) { return $candidate }
        }

        # Fall back to PATH, which covers a manual copy into the Scripts folder.
        $command = Get-Command -Name "$Script:AutopilotScript.ps1" -CommandType ExternalScript -ErrorAction SilentlyContinue |
                        Select-Object -First 1
        if ($command) { return $command.Source }

        return $null
    }

    $path = & $resolve
    if ($path) {
        Write-Log -Message "Using $Script:AutopilotScript at: $path" -Level DEBUG
        return $path
    }

    Write-Log -Message "$Script:AutopilotScript.ps1 is not installed. Installing it from the PowerShell Gallery..."
    Initialize-PSGalleryAccess
    try {
        Install-Script -Name $Script:AutopilotScript -Scope AllUsers -Force -Repository PSGallery -ErrorAction Stop
        Write-Log -Message "Installed $Script:AutopilotScript." -Level SUCCESS
    }
    catch {
        Write-ErrorRecordToLog -ErrorRecord $_ -Context "Failed to install $Script:AutopilotScript"
        Write-Log -Message "Install it manually with: Install-Script -Name $Script:AutopilotScript -Scope AllUsers" -Level WARN
        return $null
    }

    $path = & $resolve
    if (-not $path) {
        Write-Log -Message "$Script:AutopilotScript.ps1 still cannot be located after installation." -Level ERROR
    }
    return $path
}

function Get-ScriptParameterName {
    <#
        Reads the parameter names the installed Autopilot script actually accepts. Versions
        differ in what they support (certificate auth in particular), and passing an unknown
        parameter produces a confusing binding error -- better to check first and say so.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    try {
        $command = Get-Command -Name $Path -CommandType ExternalScript -ErrorAction Stop
        return @($command.Parameters.Keys)
    }
    catch {
        Write-Log -Message "Could not inspect parameters of '$Path': $($_.Exception.Message)" -Level DEBUG
        return @()
    }
}

function Invoke-EnrollThisDevice {
    <#
        Menu option 3. The one every technician runs on every machine after setup.
    #>
    [CmdletBinding()]
    param()

    Write-Header 'Enroll this device in Autopilot / Intune'
    Write-Log -Message 'Menu 3 selected: enroll this device.' -Level DEBUG

    # ---- Config --------------------------------------------------------------
    $config = Get-ToolConfig
    if (-not $config) {
        Write-Log -Message 'No saved configuration was found.' -Level ERROR
        Write-Host ''
        Write-Host '  Run option 1 (connect to an existing app registration) or option 2' -ForegroundColor Yellow
        Write-Host '  (create a new app registration) first. Configuration is stored at:' -ForegroundColor Yellow
        Write-Host "    $Script:ConfigPath" -ForegroundColor Yellow
        Pause-ForTech
        return
    }

    Write-Host "  Tenant : $($config.TenantId)"
    Write-Host "  App    : $($config.AppId)$(if ($config.AppDisplayName) { " ($($config.AppDisplayName))" })"
    Write-Host "  Cert   : $($config.CertificateThumbprint)"
    Write-Host ''

    # ---- Certificate ---------------------------------------------------------
    $certStatus = Test-ConfiguredCertificate -Thumbprint $config.CertificateThumbprint
    if (-not $certStatus.Present) {
        Write-Log -Message "The configured certificate ($($certStatus.Thumbprint)) is not present in $Script:CertStore on this machine." -Level ERROR
        Write-Host ''
        Write-Host '  The configuration was created on a different machine, or the certificate has' -ForegroundColor Yellow
        Write-Host '  been removed. Import the certificate (with its private key) into' -ForegroundColor Yellow
        Write-Host "  $Script:CertStore, or re-run option 1 to point at a certificate that is here." -ForegroundColor Yellow
        Pause-ForTech
        return
    }
    if (-not $certStatus.IsUsable) {
        Write-Log -Message "The configured certificate is unusable: $($certStatus.Summary)" -Level ERROR
        Pause-ForTech
        return
    }
    Write-Log -Message "Certificate check passed -- $($certStatus.Summary)." -Level SUCCESS

    # ---- Autopilot script ----------------------------------------------------
    Write-Host ''
    $scriptPath = Get-AutopilotInfoScript
    if (-not $scriptPath) {
        Pause-ForTech
        return
    }

    $supported = Get-ScriptParameterName -Path $scriptPath
    if ($supported.Count -gt 0 -and $supported -notcontains 'CertificateThumbprint') {
        Write-Log -Message "The installed $Script:AutopilotScript.ps1 does not accept -CertificateThumbprint." -Level ERROR
        Write-Host ''
        Write-Host '  This tool is certificate-auth only, so an older build of the Autopilot script' -ForegroundColor Yellow
        Write-Host '  that only supports -AppSecret cannot be used. Update it with:' -ForegroundColor Yellow
        Write-Host "    Install-Script -Name $Script:AutopilotScript -Scope AllUsers -Force" -ForegroundColor Yellow
        Write-Host ''
        Pause-ForTech
        return
    }

    # ---- Optional enrollment details ----------------------------------------
    Write-Host ''
    Write-Host '  Optional details -- press Enter to skip any of them.' -ForegroundColor White
    Write-Host ''

    $groupTag = Read-NonEmpty -Prompt 'Group Tag' -AllowBlank

    $assignedUser = Read-NonEmpty -Prompt 'Assigned User (UPN, e.g. jane@contoso.com)' -AllowBlank `
                                  -Validator { param($v) $v -match '^[^@\s]+@[^@\s]+\.[^@\s]+$' } `
                                  -ValidationMessage 'That does not look like a UPN. Enter user@domain.tld, or press Enter to skip.'

    $assignedComputerName = Read-NonEmpty -Prompt 'Assigned Computer Name' -AllowBlank `
                                          -Validator { param($v) $v.Length -le 15 } `
                                          -ValidationMessage 'Computer names are limited to 15 characters.'

    # ---- Build the invocation -----------------------------------------------
    $params = [ordered]@{
        Online                = $true
        TenantId              = $config.TenantId
        AppId                 = $config.AppId
        CertificateThumbprint = $config.CertificateThumbprint
    }

    foreach ($optional in @(
        @{ Key = 'GroupTag';             Value = $groupTag }
        @{ Key = 'AssignedUser';         Value = $assignedUser }
        @{ Key = 'AssignedComputerName'; Value = $assignedComputerName }
    )) {
        if ([string]::IsNullOrWhiteSpace($optional.Value)) { continue }

        if ($supported.Count -gt 0 -and $supported -notcontains $optional.Key) {
            Write-Log -Message "The installed Autopilot script does not support -$($optional.Key) -- that value will be skipped." -Level WARN
            continue
        }
        $params[$optional.Key] = $optional.Value
    }

    Write-Host ''
    Write-Host '  About to run:' -ForegroundColor White
    $preview = ($params.Keys | ForEach-Object {
        if ($params[$_] -is [bool]) { "-$_" } else { "-$_ '$($params[$_])'" }
    }) -join ' '
    Write-Host "    $Script:AutopilotScript.ps1 $preview" -ForegroundColor DarkGray
    Write-Host ''

    if (-not (Confirm-Action -Prompt 'Enroll this device now?' -DefaultYes)) {
        Write-Log -Message 'Enrollment cancelled by the technician.' -Level WARN
        Pause-ForTech
        return
    }

    # ---- Run -----------------------------------------------------------------
    Write-Host ''
    Write-Log -Message "Starting Autopilot registration for $env:COMPUTERNAME..."
    Write-Log -Message "Invoking: $scriptPath $preview" -Level DEBUG

    try {
        # $LASTEXITCODE persists from whatever ran last, so clear it first -- otherwise a
        # stale non-zero value would be misreported as a failed enrollment.
        $global:LASTEXITCODE = 0

        & $scriptPath @params
        $exitCode = $LASTEXITCODE

        if ($null -ne $exitCode -and $exitCode -ne 0) {
            throw "$Script:AutopilotScript.ps1 exited with code $exitCode."
        }

        Write-Host ''
        Write-Log -Message "Device $env:COMPUTERNAME was submitted to the Autopilot service successfully." -Level SUCCESS
        Write-Host ''
        Write-Host '  Next steps:' -ForegroundColor White
        Write-Host '    - Autopilot device sync in Intune can take a few minutes; the device will'
        Write-Host '      not appear under Devices > Windows > Windows enrollment > Devices instantly.'
        if ($groupTag) {
            Write-Host "    - Group tag '$groupTag' was submitted. Confirm the matching dynamic group"
            Write-Host '      picks the device up before you reset it.'
        }
        Write-Host '    - Reset or reimage the device once it shows in Intune to start the'
        Write-Host '      Autopilot out-of-box experience.'
        Write-Host ''
    }
    catch {
        Write-ErrorRecordToLog -ErrorRecord $_ -Context 'Autopilot enrollment failed'
        Write-Host ''
        Write-Host '  Enrollment did NOT complete. Things worth checking:' -ForegroundColor Yellow
        Write-Host '    - the app registration has DeviceManagementServiceConfig.ReadWrite.All with' -ForegroundColor Yellow
        Write-Host '      admin consent granted (option 4 shows which app is configured);' -ForegroundColor Yellow
        Write-Host '    - this machine has internet access to graph.microsoft.com;' -ForegroundColor Yellow
        Write-Host '    - the device hardware hash could be read (some VMs cannot provide one);' -ForegroundColor Yellow
        Write-Host '    - the device is not already registered to a different tenant.' -ForegroundColor Yellow
        Write-Host ''
        Write-Host "  Full detail is in $Script:LogPath" -ForegroundColor Yellow
        Write-Host ''
    }

    Pause-ForTech
}

#endregion

#region --------------------------------------------------------------- Menu 4: view config

function Show-CurrentConfiguration {
    [CmdletBinding()]
    param()

    Write-Header 'Current configuration'
    Write-Log -Message 'Menu 4 selected: view current configuration.' -Level DEBUG

    $config = Get-ToolConfig
    if (-not $config) {
        Write-Host '  This machine is not configured yet.' -ForegroundColor Yellow
        Write-Host ''
        Write-Host '  Use option 1 to connect to an existing app registration, or option 2 to'
        Write-Host '  create a new one.'
        Write-Host ''
        Write-Host "  Expected config file: $Script:ConfigPath" -ForegroundColor DarkGray
        Pause-ForTech
        return
    }

    $certStatus = Test-ConfiguredCertificate -Thumbprint $config.CertificateThumbprint

    Write-Host ('  {0,-22}: {1}' -f 'Tenant ID', $config.TenantId)
    Write-Host ('  {0,-22}: {1}' -f 'App (Client) ID', $config.AppId)
    Write-Host ('  {0,-22}: {1}' -f 'App display name', $(if ($config.AppDisplayName) { $config.AppDisplayName } else { '(not recorded)' }))
    Write-Host ('  {0,-22}: {1}' -f 'Cert thumbprint', $config.CertificateThumbprint)

    $certColour = if ($certStatus.IsUsable) { 'Green' } elseif ($certStatus.Present) { 'Red' } else { 'Red' }
    Write-Host ('  {0,-22}: ' -f 'Certificate status') -NoNewline
    Write-Host $certStatus.Summary -ForegroundColor $certColour

    if ($certStatus.Present) {
        Write-Host ('  {0,-22}: {1}' -f 'Certificate subject', $certStatus.Subject)
        if ($certStatus.IsUsable) {
            $daysLeft = [int]([math]::Floor(($certStatus.NotAfter - (Get-Date)).TotalDays))
            $daysColour = if ($daysLeft -lt 30) { 'Yellow' } else { 'Gray' }
            Write-Host ('  {0,-22}: ' -f 'Days until expiry') -NoNewline
            Write-Host $daysLeft -ForegroundColor $daysColour
        }
    }

    Write-Host ''
    Write-Host ('  {0,-22}: {1}' -f 'Configured on', $config.SavedOn) -ForegroundColor DarkGray
    Write-Host ('  {0,-22}: {1}' -f 'Configured by', $config.SavedBy) -ForegroundColor DarkGray
    Write-Host ('  {0,-22}: {1}' -f 'Source', $config.Source) -ForegroundColor DarkGray
    Write-Host ''
    Write-Host ('  {0,-22}: {1}' -f 'Config file', $Script:ConfigPath) -ForegroundColor DarkGray
    Write-Host ('  {0,-22}: {1}' -f 'Log file', $Script:LogPath) -ForegroundColor DarkGray
    Write-Host ''

    if (-not $certStatus.IsUsable) {
        Write-Host '  Enrollment (option 3) will not work until the certificate problem above is' -ForegroundColor Yellow
        Write-Host '  resolved.' -ForegroundColor Yellow
        Write-Host ''
    }

    if (Confirm-Action -Prompt 'Run a live connection test against this configuration?') {
        if (Initialize-GraphModules -Modules @('Microsoft.Graph.Authentication')) {
            Write-Host ''
            $test = Test-GraphCertificateConnection -TenantId $config.TenantId `
                                                    -AppId $config.AppId `
                                                    -CertificateThumbprint $config.CertificateThumbprint
            if ($test.Success) {
                Write-Host ''
                Write-Host "  Connection OK -- tenant: $($test.TenantName)" -ForegroundColor Green
            }
        }
    }

    Pause-ForTech
}

#endregion

#region --------------------------------------------------------------- Menu 5: manage certs

function Invoke-ManageCertificates {
    [CmdletBinding()]
    param()

    Write-Header 'Manage certificates (Cert:\LocalMachine\My)'
    Write-Log -Message 'Menu 5 selected: manage certificates.' -Level DEBUG

    $config = Get-ToolConfig
    $inUse  = if ($config) { Format-Thumbprint $config.CertificateThumbprint } else { '' }

    $certs = @(Get-CandidateCertificate)
    $null  = Show-CertificateTable -Certificates $certs

    if ($certs.Count -eq 0) {
        Pause-ForTech
        return
    }

    if ($inUse) {
        $configured = $certs | Where-Object { $_.Thumbprint -eq $inUse }
        if ($configured) {
            Write-Host "  The certificate currently in use by this tool is $inUse." -ForegroundColor Cyan
        }
        else {
            Write-Host "  Note: the configured certificate ($inUse) is not in this store." -ForegroundColor Yellow
        }
        Write-Host ''
    }

    $expired = @($certs | Where-Object { $_.NotAfter -lt (Get-Date) })
    if ($expired.Count -eq 0) {
        Write-Host '  No expired certificates to clean up.' -ForegroundColor Green
        Pause-ForTech
        return
    }

    Write-Host "  $($expired.Count) expired certificate(s) found." -ForegroundColor Yellow
    Write-Host ''
    if (-not (Confirm-Action -Prompt 'Delete expired certificates?')) {
        Write-Log -Message 'Certificate cleanup declined.' -Level DEBUG
        Pause-ForTech
        return
    }

    foreach ($cert in $expired) {
        Write-Host ''
        Write-Host "  $($cert.Subject)" -ForegroundColor White
        Write-Host "    Thumbprint : $($cert.Thumbprint)"
        Write-Host "    Expired    : $($cert.NotAfter.ToString('yyyy-MM-dd'))"

        if ($cert.Thumbprint -eq $inUse) {
            Write-Host '    This certificate is the one referenced by the saved configuration.' -ForegroundColor Yellow
            Write-Host '    Deleting it will break option 3 until you reconfigure.' -ForegroundColor Yellow
        }

        if (-not (Confirm-Action -Prompt "    Delete this certificate?")) {
            Write-Log -Message "Kept expired certificate $($cert.Thumbprint)." -Level DEBUG
            continue
        }

        try {
            Remove-Item -Path (Join-Path $Script:CertStore $cert.Thumbprint) -Force -DeleteKey -ErrorAction Stop
            Write-Log -Message "Deleted expired certificate $($cert.Thumbprint) ($($cert.Subject))." -Level SUCCESS
        }
        catch {
            Write-ErrorRecordToLog -ErrorRecord $_ -Context "Failed to delete certificate $($cert.Thumbprint)"
        }
    }

    Pause-ForTech
}

#endregion

#region --------------------------------------------------------------- Menu loop

function Show-Menu {
    [CmdletBinding()]
    param()

    $config = Get-ToolConfig
    $state  = if ($config) {
        $certStatus = Test-ConfiguredCertificate -Thumbprint $config.CertificateThumbprint
        if ($certStatus.IsUsable) { "Configured: $($config.TenantId)" }
        else { "Configured, but the certificate is not usable" }
    }
    else {
        'Not configured yet -- start with option 1 or 2'
    }

    Write-Host ''
    Write-Host ('=' * 68) -ForegroundColor DarkCyan
    Write-Host "  $Script:ToolName  v$Script:ToolVersion" -ForegroundColor Cyan
    Write-Host "  $env:COMPUTERNAME" -ForegroundColor DarkCyan
    Write-Host ('=' * 68) -ForegroundColor DarkCyan
    Write-Host "  $state" -ForegroundColor $(if ($config) { 'Green' } else { 'Yellow' })
    Write-Host ('-' * 68) -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '   1. Connect to an existing app registration'
    Write-Host '   2. Create a new app registration'
    Write-Host '   3. Enroll this device in Autopilot / Intune'
    Write-Host '   4. View current configuration'
    Write-Host '   5. Manage certificates'
    Write-Host '   6. Exit'
    Write-Host ''
}

function Start-EnrollmentTool {
    [CmdletBinding()]
    param()

    Initialize-DataStore

    Write-Log -Message ('=' * 60) -NoConsole
    Write-Log -Message "$Script:ToolName v$Script:ToolVersion started on $env:COMPUTERNAME by $env:USERDOMAIN\$env:USERNAME (PowerShell $($PSVersionTable.PSVersion))." -NoConsole

    if ($PSVersionTable.Platform -and $PSVersionTable.Platform -ne 'Win32NT') {
        Write-Log -Message 'This tool only runs on Windows -- it depends on the Windows certificate store and Autopilot hardware hash.' -Level ERROR
        return
    }

    while ($true) {
        Show-Menu

        $choice = Read-Host -Prompt 'Select an option [1-6]'
        if ($null -eq $choice) { $choice = '' }

        switch ($choice.Trim()) {
            '1' { Invoke-ConnectExistingApp }
            '2' { Invoke-CreateNewApp }
            '3' { Invoke-EnrollThisDevice }
            '4' { Show-CurrentConfiguration }
            '5' { Invoke-ManageCertificates }
            '6' {
                Write-Log -Message 'Exiting.' -NoConsole
                Disconnect-GraphQuietly
                Write-Host ''
                Write-Host '  Goodbye.' -ForegroundColor Cyan
                Write-Host ''
                return
            }
            default {
                Write-Host ''
                Write-Host '  Enter a number from 1 to 6.' -ForegroundColor Yellow
            }
        }
    }
}

#endregion

# Entry point. Everything below the menu loop is wrapped so an unexpected failure still
# gets logged and still leaves the technician with a readable message.
try {
    Start-EnrollmentTool
}
catch {
    Initialize-DataStore
    Write-ErrorRecordToLog -ErrorRecord $_ -Context 'The tool stopped unexpectedly'
    Write-Host ''
    Write-Host "  Something went wrong. Full detail is in $Script:LogPath" -ForegroundColor Red
    Write-Host ''
    exit 1
}
finally {
    Disconnect-GraphQuietly
}
