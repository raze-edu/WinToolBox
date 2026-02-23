#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Groups

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

# Auto-connect if not already connected
if (-not (Get-MgContext)) {
    Write-Host "Not connected to Microsoft Graph. Attempting interactive login..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes "User.Read.All", "GroupMember.Read.All", "Directory.Read.All" | Out-Null
}

Write-Verbose "Fetching all users..."
$users = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,Mail,JobTitle,Department,AccountEnabled,AssignedLicenses" -ExpandProperty Manager

$results = @()

$total = $users.Count
$counter = 0

foreach ($user in $users) {
    $counter++
    Write-Verbose "Processing User $counter of ${total}: $($user.UserPrincipalName)"

    # Parse Manager
    $managerData = $null
    if ($user.Manager) {
        $managerData = @{
            Id = $user.Manager.Id
            DisplayName = $user.Manager.AdditionalProperties["displayName"]
            UserPrincipalName = $user.Manager.AdditionalProperties["userPrincipalName"]
        }
    }

    # Parse Licenses directly from user properties
    $licenses = @()
    if ($user.AssignedLicenses) {
        foreach ($lic in $user.AssignedLicenses) {
            $licenses += @{
                SkuId = $lic.SkuId
            }
        }
    }

    # Fetch Groups
    $groups = @()
    try {
        $userGroups = Get-MgUserMemberOf -UserId $user.Id
        foreach ($group in $userGroups) {
            if ($group.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.group") {
                $groups += @{
                    Id = $group.Id
                    DisplayName = $group.AdditionalProperties["displayName"]
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to fetch groups for user $($user.UserPrincipalName): $_"
    }

    $results += @{
        Id = $user.Id
        DisplayName = $user.DisplayName
        UserPrincipalName = $user.UserPrincipalName
        Mail = $user.Mail
        JobTitle = $user.JobTitle
        Department = $user.Department
        AccountEnabled = $user.AccountEnabled
        Manager = $managerData
        Licenses = $licenses
        Groups = $groups
    }
}

# Output as JSON so Python can parse it easily
$results | ConvertTo-Json -Depth 5 -Compress
