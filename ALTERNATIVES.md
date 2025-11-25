# Alternative Implementation Methods

## 1. Using DPAPI Encryption (Advanced)

If you want more control without external modules:

```powershell
# encrypt.ps1 - Encrypt API token with DPAPI
param([string]$ApiToken)

$bytes = [System.Text.Encoding]::UTF8.GetBytes($ApiToken)
$encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
    $bytes, 
    $null, 
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
)
$base64 = [Convert]::ToBase64String($encrypted)

# Save to file
$base64 | Out-File -FilePath "$env:APPDATA\cloudflare_token.enc" -Force

Write-Host "Token encrypted and saved to: $env:APPDATA\cloudflare_token.enc"
```

```powershell
# purge-cf-cache-dpapi.ps1 - Use DPAPI encrypted token
param(
    [string]$ZoneId,
    [string]$Action = "PurgeAll"
)

# Read encrypted token
$base64 = Get-Content "$env:APPDATA\cloudflare_token.enc"
$encrypted = [Convert]::FromBase64String($base64)
$bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $encrypted,
    $null,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
)
$apiToken = [System.Text.Encoding]::UTF8.GetString($bytes)

# Use $apiToken for API calls...
$headers = @{
    "Authorization" = "Bearer $apiToken"
    "Content-Type"  = "application/json"
}

$payload = @{ purge_everything = $true } | ConvertTo-Json

Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$ZoneId/purge_cache" `
    -Method Post `
    -Headers $headers `
    -Body $payload
```

**Pros**: No module dependencies, tight security  
**Cons**: File-based encryption, user-account dependent

---

## 2. Using PowerShell SecretManagement (Modern)

Microsoft's official modern approach (PowerShell 7+):

```powershell
# Install modules
Install-Module Microsoft.PowerShell.SecretManagement -Scope CurrentUser
Install-Module Microsoft.PowerShell.SecretStore -Scope CurrentUser

# Register vault
Register-SecretVault -Name MySecrets -Module Microsoft.PowerShell.SecretStore

# Store secret
Set-Secret -Vault MySecrets -Name CloudflareAPI -Secret (Read-Host -AsSecureString)

# Retrieve in script
$apiToken = Get-Secret -Vault MySecrets -Name CloudflareAPI -AsPlainText
```

**Pros**: Modern, Microsoft-backed, cross-platform  
**Cons**: Requires PowerShell 7+, more infrastructure

---

## 3. Using Bitwarden Secrets Manager (Team-Friendly)

Best for organizations or CI/CD:

```powershell
# Install
choco install bitwarden-cli

# Login
bw login

# Store secret (one-time)
$env:BW_SESSION = bw unlock --raw --passwordenv BW_PASSWORD
$secretJson = @{
    type = 2
    name = "Cloudflare API Token"
    login = @{
        uri = "https://api.cloudflare.com"
        username = "api"
        password = "YOUR_API_TOKEN_HERE"
    }
} | ConvertTo-Json

bw create item $secretJson --organizationid YOUR_ORG_ID

# Retrieve in script
$bwLock = if ($null -eq $env:BW_SESSION) { $true } else { $false }

if ($bwLock) {
    $env:BW_SESSION = bw unlock --raw
}

$secret = bw get item cloudflare-api | ConvertFrom-Json
$apiToken = $secret.login.password

# Now use $apiToken...
```

**Pros**: Team sharing, audit logs, cloud-backed, CI/CD friendly  
**Cons**: Requires Bitwarden account, more setup

---

## 4. Using Azure Key Vault (Enterprise)

For enterprise environments integrated with Azure:

```powershell
# Prerequisites
Install-Module Az.KeyVault -Scope CurrentUser

Connect-AzAccount

# Store secret
Set-AzKeyVaultSecret -VaultName "MyKeyVault" `
    -Name "CloudflareAPIToken" `
    -SecretValue (ConvertTo-SecureString "YOUR_TOKEN" -AsPlainText -Force)

# Retrieve in script
$apiToken = (Get-AzKeyVaultSecret -VaultName "MyKeyVault" `
    -Name "CloudflareAPIToken" -AsPlainText)

# Use for purge...
```

**Pros**: Enterprise integration, role-based access, audit logs  
**Cons**: Requires Azure account, network calls

---

## 5. Using KeePass (Local Database)

For organizations using KeePass for credential management:

```powershell
# Install module
Install-Module PoShKeePass -Scope CurrentUser

# Open database (prompts for password)
$keepassDb = Get-KeePassDatabaseConfiguration
New-KeePassDatabaseSession -KeePassDatabase $keepassDb

# Get entry
$entry = Get-KeePassEntry -Title "Cloudflare API"
$apiToken = $entry.Strings.UserName  # or .Password

# Use for purge...
```

**Pros**: Local database, no external services  
**Cons**: Requires KeePass and PowerShell module

---

## 6. Using Environment Variables (Simple but Risky)

⚠️ **NOT RECOMMENDED** for sensitive credentials, but simpler:

```powershell
# Set environment variable (in current session only)
$env:CLOUDFLARE_API_TOKEN = Read-Host -Prompt "Enter API token" -AsSecureString

# In script
$apiToken = $env:CLOUDFLARE_API_TOKEN

# For persistent (Windows):
[Environment]::SetEnvironmentVariable("CLOUDFLARE_API_TOKEN", $apiToken, "User")
```

**Pros**: Simplest, no modules  
**Cons**: Visible in process memory, weak isolation, NOT for production

---

## Comparison Matrix

| Method | Setup Time | Security | Team-Friendly | Single-Machine | Requires Module | Enterprise-Ready |
|--------|-----------|----------|---------------|---|---|---|
| **Credential Manager** | 5 min | ★★★★★ | ❌ | ✅ | ❌ | ⚠️  |
| **DPAPI File** | 10 min | ★★★★☆ | ❌ | ✅ | ❌ | ❌ |
| **SecretManagement** | 10 min | ★★★★★ | ⚠️  | ✅ | ✅ | ✅ |
| **Bitwarden** | 15 min | ★★★★★ | ✅ | ✅ | ❌ | ✅ |
| **Azure Key Vault** | 20 min | ★★★★★ | ✅ | ⚠️  | ✅ | ✅ |
| **KeePass** | 15 min | ★★★★☆ | ⚠️  | ✅ | ✅ | ⚠️  |
| **Env Variables** | 2 min | ★☆☆☆☆ | ✅ | ✅ | ❌ | ❌ |

---

## Migration Guide

### From Plaintext Config File → Credential Manager

```powershell
# Old approach (DON'T DO THIS)
# $config = @{
#     ApiToken = "cfv1_abc123..."
# } | ConvertTo-Json
# $config | Out-File config.json

# New approach
# 1. Run setup (creates secure credential)
.\purge-cf-cache.ps1 -Action Setup

# 2. Delete old config file
Remove-Item config.json -Force

# 3. Update scripts to use new method
# (use the provided purge-cf-cache.ps1 script)
```

### From DPAPI File → Credential Manager

```powershell
# 1. Decrypt old token
$base64 = Get-Content "$env:APPDATA\cloudflare_token.enc"
$encrypted = [Convert]::FromBase64String($base64)
$bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser
)
$apiToken = [System.Text.Encoding]::UTF8.GetString($bytes)

# 2. Store in Credential Manager
$cred = New-Object System.Management.Automation.PSCredential(
    "cloudflare",
    (ConvertTo-SecureString $apiToken -AsPlainText -Force)
)
New-StoredCredential -Target "CloudflareAPI" -Credential $cred -Type Generic

# 3. Delete old file
Remove-Item "$env:APPDATA\cloudflare_token.enc" -Force
```

---

## Security Audit Checklist

- [ ] Never committed plaintext API tokens to Git
- [ ] API token not visible in process memory (using secure storage)
- [ ] Token rotated within last 6 months
- [ ] Token has minimal permissions (Cache Purge only)
- [ ] Token scoped to specific zones (not "All zones")
- [ ] Credential storage method requires authentication
- [ ] Old/backup tokens have been deleted
- [ ] Cloudflare audit log reviewed recently
- [ ] Script file not shared insecurely
- [ ] Scheduled tasks running with least privileges

---

## Recommended Choice for Your Setup

Based on your profile:

✅ **Start with**: Windows Credential Manager (main script)  
- Simple, built-in, secure
- Perfect for personal workstations
- No dependencies beyond PowerShell

📈 **Level up to**: PowerShell SecretManagement  
- More flexible if managing multiple secrets
- Still local but modern approach

🔄 **Consider later**: Bitwarden if collaborating with team  
- Share access without sharing tokens
- Cloud sync across machines
- Audit trail
