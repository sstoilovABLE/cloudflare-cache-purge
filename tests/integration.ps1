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
    if (Get-Command -Name New-StoredCredential -ErrorAction SilentlyContinue) {
        New-StoredCredential -Target ("CloudflarePurgeTool:$testName") -Credential (New-Object System.Management.Automation.PSCredential("CF", $sec)) -Type Generic -Persist LocalMachine | Out-Null
        Write-Host "Created test credential via New-StoredCredential: $testName" -ForegroundColor Green
    } else {
        Write-Host "New-StoredCredential not available in this environment; skipping automated credential creation. Skipping remainder of test." -ForegroundColor Yellow
        exit 0
    }

    # List and assert presence
    $list = List-StoredConfigs -ShowZone
    if ($list -match $testName) { Write-Host "ListConfigs contains $testName" -ForegroundColor Green } else { Write-Host "ListConfigs did NOT find $testName" -ForegroundColor Red; exit 1 }

    # Get stored config directly
    $cfg = Get-StoredConfig -FriendlyName $testName
    if ($cfg.ZoneId -and $cfg.Token) { Write-Host "Get-StoredConfig returned object for $testName" -ForegroundColor Green } else { Write-Host "Get-StoredConfig failed" -ForegroundColor Red; exit 1 }

    Write-Host "Integration smoke test passed." -ForegroundColor Green
} finally {
    # Clean up
    try { Remove-StoredCredential -Target ("CloudflarePurgeTool:$testName") -ErrorAction SilentlyContinue } catch { }
    # Fallback: cmdkey delete
    try { cmdkey /delete:"CloudflarePurgeTool:$testName" 2>$null } catch { }
    Write-Host "Cleaned up test credential." -ForegroundColor Gray
}
