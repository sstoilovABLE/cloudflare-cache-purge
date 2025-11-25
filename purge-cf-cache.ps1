#!/usr/bin/env pwsh
param(
    [ValidateSet('SaveConfig', 'PurgeAll', 'PurgeUrls', 'PurgeTags', 'Verify')]
    [string]$Action = 'PurgeAll',
    [Parameter(Mandatory=$true)][string]$FriendlyName,
    [string]$ZoneId,
    [string[]]$Urls,
    [string[]]$Tags
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

Write-Host "`nCloudflare Tool: $Action ($FriendlyName)" -ForegroundColor Cyan

switch ($Action) {
    'SaveConfig' {
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
        Assert-UserPresence
        $c = Get-StoredConfig
        Write-Host "Found Config -> Zone: $($c.ZoneId)" -ForegroundColor Green
    }
    'PurgeAll' {
        Assert-UserPresence
        $c = Get-StoredConfig
        Invoke-CFRequest -Token $c.Token -ZId $c.ZoneId -Payload @{ purge_everything=$true }
    }
    'PurgeUrls' {
        if (-not $Urls) { throw "-Urls required" }
        Assert-UserPresence
        $c = Get-StoredConfig
        Invoke-CFRequest -Token $c.Token -ZId $c.ZoneId -Payload @{ files=$Urls }
    }
    'PurgeTags' {
        if (-not $Tags) { throw "-Tags required" }
        Assert-UserPresence
        $c = Get-StoredConfig
        Invoke-CFRequest -Token $c.Token -ZId $c.ZoneId -Payload @{ tags=$Tags }
    }
    default { throw "Unknown Action" }
}
Write-Host ""
