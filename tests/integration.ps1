# Integration helper test (non-interactive parts)
# This script creates a temporary stored credential, lists configs, reads it back via Get-StoredConfig,
# then cleans up. It does not attempt interactive Windows Hello flows.

if (-not (Get-Module -ListAvailable 'CredentialManager')) {
    Write-Host "CredentialManager module not found. Install it before running this test.`nInstall-Module -Name CredentialManager -Scope CurrentUser -Force" -ForegroundColor Yellow
    exit 2
}

# Ensure module functions are available
Import-Module CredentialManager -ErrorAction Stop

. $PSScriptRoot\..\purge-cf-cache.ps1

$testName = "test-integration-$(Get-Random)"
$payload = @{ Token = "test-token-$(Get-Random)"; ZoneId = "zone-test-$(Get-Random)" } | ConvertTo-Json -Compress
$sec = ConvertTo-SecureString $payload -AsPlainText -Force

try {
    # Prefer to use CredentialManager's New-StoredCredential when available (works on Windows PowerShell)
    $created = $false
    $createdWithModule = $false
    if (Get-Command -Name New-StoredCredential -ErrorAction SilentlyContinue) {
        try {
            New-StoredCredential -Target ("CloudflarePurgeTool:$testName") -Credential (New-Object System.Management.Automation.PSCredential("CF", $sec)) -Type Generic -Persist LocalMachine | Out-Null
            Write-Host "Created test credential via New-StoredCredential: $testName" -ForegroundColor Green
            $created = $true
            $createdWithModule = $true
        } catch {
            Write-Warning "New-StoredCredential invocation failed: $_"
        }
    }

    if (-not $created) {
        # Try cmdkey fallback (best-effort) with a simple password string; if that fails, skip the test gracefully.
        try {
            $simplePass = "test-pass-$([guid]::NewGuid().ToString())"
            cmdkey /generic:"CloudflarePurgeTool:$testName" /user:CF /pass:$simplePass 2>&1 | Out-Null
            Write-Host "Created test credential via cmdkey: $testName" -ForegroundColor Green
            $created = $true
        } catch {
            Write-Host "Failed to create credential via New-StoredCredential and cmdkey; skipping remainder of test." -ForegroundColor Yellow
            exit 0
        }
    }

    # List and assert presence
    $list = List-StoredConfigs -ShowZone
    $names = @()
    if ($list) { $names = $list | ForEach-Object { if ($_ -is [string]) { $_ } else { $_.FriendlyName } } }
    if ($names -contains $testName) { Write-Host "ListConfigs contains $testName" -ForegroundColor Green } else { Write-Host "ListConfigs did NOT find $testName" -ForegroundColor Red; exit 1 }

    # Get stored config directly (only if created via CredentialManager module)
    if ($createdWithModule) {
        $cfg = Get-StoredConfig -FriendlyName $testName
        if ($cfg.ZoneId -and $cfg.Token) { Write-Host "Get-StoredConfig returned object for $testName" -ForegroundColor Green } else { Write-Host "Get-StoredConfig failed" -ForegroundColor Red; exit 1 }
    } else {
        Write-Host "Skipped Get-StoredConfig - credential created via cmdkey fallback." -ForegroundColor Yellow
    }

    # Remove using our script function (non-interactive)
    Remove-StoredConfig -FriendlyName $testName -Force
    # Verify it's gone
    $listAfter = List-StoredConfigs -ShowZone
    $namesAfter = @()
    if ($listAfter) { $namesAfter = $listAfter | ForEach-Object { if ($_ -is [string]) { $_ } else { $_.FriendlyName } } }
    if ($namesAfter -contains $testName) { Write-Host "Remove-StoredConfig failed - $testName still present" -ForegroundColor Red; exit 1 } else { Write-Host "Remove-StoredConfig removed $testName" -ForegroundColor Green }

    Write-Host "Integration smoke test passed." -ForegroundColor Green
} finally {
    # Clean up
    try { Remove-StoredCredential -Target ("CloudflarePurgeTool:$testName") -ErrorAction SilentlyContinue } catch { }
    # Fallback: cmdkey delete
    try { cmdkey /delete:"CloudflarePurgeTool:$testName" 2>$null } catch { }
    Write-Host "Cleaned up test credential." -ForegroundColor Gray
}
