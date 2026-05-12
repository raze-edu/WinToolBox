<#
.SYNOPSIS
    Clean uninstall script for Autodesk products.
.DESCRIPTION
    Based on instructions from: https://www.autodesk.com/support/technical/article/caas/sfdcarticles/sfdcarticles/Clean-uninstall.html
    This script removes licensing/identity manager components, residual files and folders, and registry keys.
    It processes user-specific paths (AppData and Registry) for ALL users.
.NOTES
    Run as Administrator.
#>

# Ensure running as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Please run this script as an Administrator."
    Exit
}

Write-Host "NOTE: It is recommended to uninstall main Autodesk products via Control Panel before running this cleanup script." -ForegroundColor Yellow
Write-Host "Proceeding with clean up of leftover components, files, and registry entries..." -ForegroundColor Cyan

# 1. Uninstall Licensing & Service Components and Identity Manager
$UninstallPaths = @(
    "C:\Program Files\Autodesk\AdODIS\V1\RemoveODIS.exe",
    "C:\Program Files (x86)\Common Files\Autodesk Shared\AdskLicensing\uninstall.exe",
    "C:\Program Files\Autodesk\AdskIdentityManager\uninstall.exe"
)

foreach ($Path in $UninstallPaths) {
    if (Test-Path $Path) {
        Write-Host "Running uninstaller: $Path"
        # Try to run silently if supported
        Start-Process -FilePath $Path -ArgumentList "--mode unattended" -Wait -NoNewWindow -ErrorAction SilentlyContinue
    }
}

# 2. Stop Autodesk Services and Processes
$Services = @("AdskLicensingService")
foreach ($Service in $Services) {
    if (Get-Service -Name $Service -ErrorAction SilentlyContinue) {
        Write-Host "Stopping service $Service"
        Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
    }
}

$Processes = @("AdskLicensingService", "AdskIdentityManager", "AdAppMgrSvc", "AutodeskDesktopApp", "AdSSO")
foreach ($Process in $Processes) {
    Stop-Process -Name $Process -Force -ErrorAction SilentlyContinue
}

# 3. Remove Global Files and Folders
$GlobalFolders = @(
    "C:\ProgramData\Autodesk",
    "C:\ProgramData\Autodesk Shared",
    "C:\Program Files\Autodesk",
    "C:\Program Files\Common Files\Autodesk Shared",
    "C:\Program Files (x86)\Autodesk",
    "C:\Program Files (x86)\Common Files\Autodesk Shared"
)

foreach ($Folder in $GlobalFolders) {
    if (Test-Path $Folder) {
        Write-Host "Removing folder: $Folder"
        Remove-Item -Path $Folder -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Remove FLEXnet adsk* files
if (Test-Path "C:\ProgramData\FLEXnet") {
    Write-Host "Removing FLEXnet adsk* files..."
    Get-ChildItem -Path "C:\ProgramData\FLEXnet\adsk*" -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}

# 4. Remove Global Registry Keys
$GlobalRegKeys = @(
    "HKLM:\SOFTWARE\Autodesk",
    "HKLM:\SOFTWARE\WOW6432Node\Autodesk"
)

foreach ($Key in $GlobalRegKeys) {
    if (Test-Path $Key) {
        Write-Host "Removing registry key: $Key"
        Remove-Item -Path $Key -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# 5. Process ALL User Profiles (Files and Registry)
Write-Host "Cleaning up AppData and Registry for all user profiles..." -ForegroundColor Cyan

$UserProfiles = Get-ChildItem "C:\Users" -Directory -Force

foreach ($Profile_ in $UserProfiles) {
    $ProfilePath = $Profile_.FullName
    $UserName = $Profile_.Name
    
    Write-Host "Processing User Profile: $UserName"
    
    # 5a. Files
    $AppDataRoaming = Join-Path $ProfilePath "AppData\Roaming\Autodesk"
    $AppDataLocal = Join-Path $ProfilePath "AppData\Local\Autodesk"
    $TempFolder = Join-Path $ProfilePath "AppData\Local\Temp"
    
    if (Test-Path $AppDataRoaming) {
        Write-Host "  Removing $AppDataRoaming"
        Remove-Item -Path $AppDataRoaming -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $AppDataLocal) {
        Write-Host "  Removing $AppDataLocal"
        Remove-Item -Path $AppDataLocal -Recurse -Force -ErrorAction SilentlyContinue
    }
    # Clear temp files
    if (Test-Path $TempFolder) {
        Write-Host "  Cleaning Temp folder for $UserName"
        Get-ChildItem -Path $TempFolder -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }

    # 5b. Registry (NTUSER.DAT)
    $NTUserDat = Join-Path $ProfilePath "NTUSER.DAT"
    if (Test-Path $NTUserDat) {
        $HiveName = "TempHive_$UserName"
        $HiveLoaded = $false
        
        # Check if the user's hive is already loaded in HKU
        $SID = $null
        try {
            $ObjUser = New-Object System.Security.Principal.NTAccount($UserName)
            $SID = $ObjUser.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            # Ignore if user not found via NTAccount (e.g. deleted user but profile remains)
        }
        
        $TargetRegKey = $null
        
        if ($SID -and (Test-Path "Registry::HKEY_USERS\$SID")) {
            $TargetRegKey = "Registry::HKEY_USERS\$SID\SOFTWARE\Autodesk"
        }
        else {
            # Attempt to safely load the offline hive
            $LoadResult = reg load "HKU\$HiveName" "$NTUserDat" 2>&1
            if ($LASTEXITCODE -eq 0) {
                $HiveLoaded = $true
                $TargetRegKey = "Registry::HKEY_USERS\$HiveName\SOFTWARE\Autodesk"
            }
        }
        
        if ($TargetRegKey -and (Test-Path $TargetRegKey)) {
            Write-Host "  Removing registry key: $TargetRegKey"
            Remove-Item -Path $TargetRegKey -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        if ($HiveLoaded) {
            # Run garbage collection so powershell releases open registry handles
            [gc]::Collect()
            [gc]::WaitForPendingFinalizers()
            $UnloadResult = reg unload "HKU\$HiveName" 2>&1
        }
    }
}

Write-Host "Cleanup complete!" -ForegroundColor Green
Write-Host "Please remember that Autodesk Genuine Service might still need to be manually uninstalled via Control Panel if it wasn't already configured to do so automatically." -ForegroundColor Yellow
