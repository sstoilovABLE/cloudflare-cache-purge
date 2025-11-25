# Cloudflare Purge Tool - Secure Windows Guide

This guide explains how to use the `purge-cf-cache.ps1` script to securely manage and purge your Cloudflare cache from the command line.

The script securely stores your Cloudflare **API Token** and **Zone ID** together under a friendly name (like "my-blog") in the Windows Credential Manager.

## Quick Start

### 1. Prerequisite: Install `CredentialManager`

Open PowerShell and run this command once:

```powershell
Install-Module -Name CredentialManager -Scope CurrentUser -Force
```


### 2. Save Your First Site Configuration

This step securely saves your API Token and Zone ID under a friendly name. You only need to do this once per site.

```powershell
.\purge-cf-cache.ps1 -Action SaveConfig -FriendlyName "my-blog" -ZoneId "f8c79susfcf8usf8su9c8s787f"
```

A secure "Windows PowerShell credential request" dialog will pop up:

1. **User name**: Ignore this field (it's a placeholder).
2. **Password**: Paste your **Cloudflare API Token** here.
3. Click **OK**.

Your configuration is now saved and encrypted.

### 3. Purge Cache Using the Friendly Name

Now you can purge cache without needing to look up the Zone ID or token again.

**Purge everything:**

```powershell
.\purge-cf-cache.ps1 -Action PurgeAll -FriendlyName "my-blog.bg"
```

**Purge specific URLs:**

```powershell
.\purge-cf-cache.ps1 -Action PurgeUrls -FriendlyName "my-blog.bg" -Urls @("https://my-blog.bg/", "https://my-blog.bg/news/")
```

**Purge by cache tags:**

```powershell
.\purge-cf-cache.ps1 -Action PurgeTags -FriendlyName "my-blog.bg" -Tags @("header", "footer")
```


### 4. Verify a Saved Configuration

You can check if a configuration is stored correctly at any time.

```powershell
.\purge-cf-cache.ps1 -Action Verify -FriendlyName "my-blog.bg"
```


***

## Security Architecture

### Where Your Data Is Stored

Your configurations are stored in the **Windows Credential Manager**. You can view the entries here:
`Control Panel > Credential Manager > Windows Credentials`

### How It's Protected

* **Encryption at Rest**: All data is encrypted using Windows Data Protection API (DPAPI), which is tied to your user account. No one else on the PC can read it.
* **Interactive User Consent**: When you run a purge command, the script attempts to trigger a **Windows Hello** prompt (fingerprint, face, or PIN) to verify you are actively present. This prevents a script running silently in the background from using your credentials.
* **No Plaintext Files**: Unlike config files, this method ensures your sensitive API token is never stored in a readable file on your disk.


### Credential Details

For each friendly name you save, a new entry is created:


| Property | Example Value |
| :-- | :-- |
| **Target** | `CloudflarePurgeTool:my-blog.bg` |
| **Username** | `CF` (a placeholder) |
| **Password** | An encrypted JSON payload: `{"Token": "...", "ZoneId": "..."}` |


***

## Troubleshooting

### Error: "Config 'my-blog.bg' not found."

**Solution**: You haven't saved the configuration for that friendly name yet. Run the `SaveConfig` action first:

```powershell
.\purge-cf-cache.ps1 -Action SaveConfig -FriendlyName "my-blog.bg" -ZoneId "your-zone-id"
```


### Error: "CredentialManager module not found."

**Solution**: The required PowerShell module is missing. Install it:

```powershell
Install-Module -Name CredentialManager -Scope CurrentUser -Force
```


### API Errors (e.g., "invalid_request", "unauthorized")

**Check**:

- Is the API token you pasted correct and not expired?
- Does the token have the necessary "Cache Purge: Edit" permissions in Cloudflare?
- Is the Zone ID correct for the domain you are trying to purge?

***

## API Token Permissions

When creating your Cloudflare API token, use the "Edit" template for "Cache Purge" for a specific zone.

* **Permissions**: `Zone` | `Cache Purge` | `Edit`
* **Zone Resources**: `Include` | `Specific zone` | `your-domain.com`