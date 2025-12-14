#!/usr/bin/env pwsh
param(
    [ValidateSet('SaveConfig', 'PurgeAll', 'PurgeUrls', 'PurgeTags', 'Verify', 'ListConfigs', 'RevealToken', 'RemoveConfig')]
    [string]$Action = 'PurgeAll',
    [string]$FriendlyName,
    [string]$ZoneId,
    [string[]]$Urls,
    [string[]]$Tags
    , [switch]$CopyToClipboard
    , [switch]$ShowToken
    , [switch]$ShowZone
    , [switch]$Force
)

$ErrorActionPreference = "Stop"
$ApiUrl = "https://api.cloudflare.com/client/v4/zones"
$CredPrefix = "CloudflarePurgeTool:"

function Assert-UserPresence {
    <# Robust Windows Hello check that avoids GetAwaiter() issues #>
    try {
        $typeName = "Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime"
        if (-not ([Type]::GetType($typeName, $false))) { return }
        
        # Check Availability
        $asyncOp = [Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()
        while ($asyncOp.Status -eq "Started") { Start-Sleep -Milliseconds 50 }
        
        if ($asyncOp.GetResults() -eq "Available") {
            Write-Host "🔐 Verification Required ($FriendlyName)" -ForegroundColor Yellow
            
            # Request Verification
            $asyncOp = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync("Approve Purge for $FriendlyName")
            while ($asyncOp.Status -eq "Started") { Start-Sleep -Milliseconds 100 }
            
            if ($asyncOp.GetResults() -ne "Verified") { 
                throw "ACCESS DENIED: User verification failed or was cancelled." 
            }
            Write-Host "✓ Verified" -ForegroundColor Green
        }
    } catch { 
        Write-Warning "Windows Hello check skipped: $_" 
    }
}

function Get-StoredConfig {
    param([Parameter(Mandatory=$true)][string]$FriendlyName)

    if (-not (Get-Module -ListAvailable "CredentialManager")) { throw "Install 'CredentialManager' module first." }

    # Retrieve raw credential object
    $cred = Get-StoredCredential -Target "$CredPrefix$FriendlyName"
    if (-not $cred) { throw "Config '$FriendlyName' not found. Run with -Action SaveConfig first." }

    $secret = $cred.Password

    # Universal method to get plain text from SecureString OR String
    if ($secret -is [System.Security.SecureString]) {
        $secret = (New-Object System.Net.NetworkCredential("", $secret)).Password
    }

    return $secret | ConvertFrom-Json
}

function List-StoredConfigs {
    param([switch]$ShowZone)

    # Attempt to use cmdkey to enumerate targets; CredentialManager module lacks a simple enumeration helper
    $prefix = "$CredPrefix"
    $targets = @()
    try {
        $cmdRaw = cmdkey /list 2>&1
        foreach ($line in $cmdRaw) {
            if ($line -match '^[ \t]*Target:\s*(.+)$') {
                $raw = $Matches[1].Trim()
                # cmdkey often prints 'LegacyGeneric:target=CloudflarePurgeTool:NAME' - extract after 'target=' if present
                if ($raw -match 'target=(.+)$') { $target = $Matches[1].Trim() } else { $target = $raw }
                if ($target -like "$prefix*") { $targets += $target }
            }
        }
    } catch {
        Write-Warning "Could not enumerate credentials via cmdkey: $_"
    }

    if (-not $targets) { Write-Host "No saved Cloudflare configs found." -ForegroundColor Yellow; return }

    if (Get-Command -Name Get-StoredCredential -ErrorAction SilentlyContinue) {
        $results = foreach ($t in $targets) {
            try {
                $c = Get-StoredCredential -Target $t
                if ($c) {
                    $json = $c.Password
                    if ($json -is [System.Security.SecureString]) {
                        $json = (New-Object System.Net.NetworkCredential("", $json)).Password
                    }
                    try {
                        $obj = $json | ConvertFrom-Json
                    } catch {
                        # Not JSON - fall back to treating the stored string as a token (ZoneId unknown)
                        $obj = [PSCustomObject]@{ Token = $json; ZoneId = $null }
                    }

                    [PSCustomObject]@{
                        FriendlyName = $t -replace "^$prefix",""
                        ZoneId = if ($ShowZone) { $obj.ZoneId } else { if ($obj.ZoneId -and $obj.ZoneId.Length -gt 6) { $obj.ZoneId.Substring(0,6) + '...' } else { $obj.ZoneId } }
                    }
                }
            } catch {
                Write-Warning "Failed reading $t - $_"
            }
        }

        # Return objects so callers/tests can capture results
        $results
    } else {
        Write-Warning "CredentialManager cmdlets not available in this shell; showing friendly names only. Use Windows PowerShell or install the CredentialManager module to reveal zones or tokens."
        $friendlyNames = @()
        foreach ($t in $targets) {
            $n = $t -replace "^$prefix",""
            $friendlyNames += $n
            Write-Host $n -ForegroundColor Cyan
        }
        return $friendlyNames
    }
}

function Reveal-StoredToken {
    param(
        [Parameter(Mandatory=$true)][string]$FriendlyName,
        [switch]$CopyToClipboard,
        [switch]$ShowToken
    )

    # Windows Hello verification if available
    Assert-UserPresence

    # Fallback typed confirmation when Windows Hello isn't present/verified
    $confirmation = Read-Host -Prompt "Type the friendly name '$FriendlyName' to confirm you want to reveal the token (or press Enter to cancel)"
    if ($confirmation -ne $FriendlyName) { throw "Confirmation mismatch - aborting." }

    $c = Get-StoredConfig -FriendlyName $FriendlyName
    if (-not $c) { throw "Config not found" }

    if ($CopyToClipboard) {
        try {
            if (Get-Command -Name Set-Clipboard -ErrorAction SilentlyContinue) {
                Set-Clipboard -Value $c.Token
            } else {
                # Fallback to clip.exe
                $c.Token | clip
            }
            Write-Host "Token copied to clipboard (until next clipboard change)." -ForegroundColor Yellow
        } catch { Write-Warning "Failed to copy to clipboard: $_" }
        return
    }

    # Default: Show masked token and require explicit ShowToken to print it
    if (-not $ShowToken) {
        $t = $c.Token
        if ($t.Length -gt 16) { $mask = $t.Substring(0,8) + '...' + $t.Substring($t.Length - 8) } else { $mask = ('*' * ($t.Length)) }
        Write-Host "Token (masked): $mask" -ForegroundColor Yellow
        Write-Host "Rerun with -ShowToken to display token in console or -CopyToClipboard to copy it." -ForegroundColor Gray
        return
    }

    # Explicit printing
    Write-Host "Token (plaintext): $($c.Token)" -ForegroundColor Red
}

function Remove-StoredConfig {
    param(
        [Parameter(Mandatory=$true)][string]$FriendlyName,
        [switch]$Force
    )

    if (-not $FriendlyName) { throw "FriendlyName is required" }

    if (-not $Force) {
        # Interactive flow: require presence and typed confirmation
        Assert-UserPresence
        $confirmation = Read-Host -Prompt "Type the friendly name '$FriendlyName' to confirm deletion (or press Enter to cancel)"
        if ($confirmation -ne $FriendlyName) { throw "Confirmation mismatch - aborting." }
    } else {
        # Non-interactive: try presence check but don't fail if unavailable
        try { Assert-UserPresence } catch { Write-Warning "User presence verification failed/ignored due to -Force: $_" }
    }

    $target = "$CredPrefix$FriendlyName"
    $deleted = $false

    # Prefer using module cmdlet when available
    if (Get-Command -Name Remove-StoredCredential -ErrorAction SilentlyContinue) {
        try {
            Remove-StoredCredential -Target $target -ErrorAction Stop
            $deleted = $true
        } catch {
            Write-Warning "Remove-StoredCredential failed: $_"
        }
    }

    if (-not $deleted) {
        try {
            cmdkey /delete:"$target" 2>&1 | Out-Null
            $deleted = $true
        } catch {
            Write-Warning "cmdkey delete failed: $_"
        }
    }

    # Verify deletion
    $stillExists = $false
    if (Get-Command -Name Get-StoredCredential -ErrorAction SilentlyContinue) {
        try {
            $s = Get-StoredCredential -Target $target -ErrorAction SilentlyContinue
            if ($s) { $stillExists = $true }
        } catch { $stillExists = $true }
    } else {
        try {
            $cmdRaw = cmdkey /list 2>&1
            foreach ($line in $cmdRaw) {
                if ($line -match '^[ \t]*Target:\s*(.+)$') {
                    $raw = $Matches[1].Trim()
                    if ($raw -match 'target=(.+)$') { $t = $Matches[1].Trim() } else { $t = $raw }
                    if ($t -eq $target) { $stillExists = $true; break }
                }
            }
        } catch { }
    }

    if ($stillExists) { throw "Failed to remove '$FriendlyName' ($target); still present." }

    Write-Host "Removed '$FriendlyName' successfully." -ForegroundColor Green
}

function Invoke-CFRequest {
    param($Token, $ZId, $Payload)
    $h = @{ "Authorization" = "Bearer $Token"; "Content-Type" = "application/json" }
    $uri = "$ApiUrl/$ZId/purge_cache"
    try {
        $resp = Invoke-RestMethod -Uri $uri -Method Post -Headers $h -Body ($Payload | ConvertTo-Json -Depth 9) -ErrorAction Stop
        if ($resp.success) { 
            Write-Host "SUCCESS" -ForegroundColor Green
            if ($resp.result) { $resp.result | ConvertTo-Json -Depth 5 | Write-Host }
            else { Write-Host "Command completed successfully." -ForegroundColor Gray }
        } else { throw "API Error: $($resp.errors | ConvertTo-Json -Depth 5)" }
    } catch { Write-Error "Request Failed: $_"; exit 1 }
}

if ($MyInvocation.InvocationName -ne '.') {
    Write-Host "`nCloudflare Tool: $Action ($FriendlyName)" -ForegroundColor Cyan

    switch ($Action) {
    'SaveConfig' {
        if (-not $FriendlyName) { throw "-FriendlyName is required for SaveConfig" }
        if (-not $ZoneId) { throw "-ZoneId is required" }
        
        # Use GUI prompt for secure token entry
        $credInput = Get-Credential -UserName "TokenInput" -Message "Paste your Cloudflare API Token as the Password"
        $plainToken = $credInput.GetNetworkCredential().Password
        
        $json = @{ Token=$plainToken; ZoneId=$ZoneId } | ConvertTo-Json -Compress
        $secJson = ConvertTo-SecureString $json -AsPlainText -Force
        
        New-StoredCredential -Target "$CredPrefix$FriendlyName" -Credential (New-Object System.Management.Automation.PSCredential("CF", $secJson)) -Type Generic -Persist LocalMachine | Out-Null
        Write-Host "Saved '$FriendlyName' securely." -ForegroundColor Green
    }
    'Verify' {
        if (-not $FriendlyName) { throw "-FriendlyName is required for Verify" }
        Assert-UserPresence
        $c = Get-StoredConfig -FriendlyName $FriendlyName
        Write-Host "Found Config -> Zone: $($c.ZoneId)" -ForegroundColor Green
    }
    'PurgeAll' {
        if (-not $FriendlyName) { throw "-FriendlyName is required for PurgeAll" }
        Assert-UserPresence
        $c = Get-StoredConfig -FriendlyName $FriendlyName
        Invoke-CFRequest -Token $c.Token -ZId $c.ZoneId -Payload @{ purge_everything=$true }
    }
    'PurgeUrls' {
        if (-not $Urls) { throw "-Urls required" }
        Assert-UserPresence
        if (-not $FriendlyName) { throw "-FriendlyName is required for PurgeUrls" }
        $c = Get-StoredConfig -FriendlyName $FriendlyName
        Invoke-CFRequest -Token $c.Token -ZId $c.ZoneId -Payload @{ files=$Urls }
    }
    'PurgeTags' {
        if (-not $Tags) { throw "-Tags required" }
        Assert-UserPresence
        if (-not $FriendlyName) { throw "-FriendlyName is required for PurgeTags" }
        $c = Get-StoredConfig -FriendlyName $FriendlyName
        Invoke-CFRequest -Token $c.Token -ZId $c.ZoneId -Payload @{ tags=$Tags }
    }
    'ListConfigs' {
        List-StoredConfigs -ShowZone:$ShowZone
    }
    'RevealToken' {
        if (-not $FriendlyName) { throw "-FriendlyName is required for RevealToken" }
        Reveal-StoredToken -FriendlyName $FriendlyName -CopyToClipboard:$CopyToClipboard -ShowToken:$ShowToken
    }
    'RemoveConfig' {
        if (-not $FriendlyName) { throw "-FriendlyName is required for RemoveConfig" }
        Remove-StoredConfig -FriendlyName $FriendlyName -Force:$Force
    }
    default { throw "Unknown Action" }
    }
    Write-Host ""
}
