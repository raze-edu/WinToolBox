[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("users", "devices")]
    [string]$Type
)

# Force UTF-8 encoding for output
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Ensure ActiveDirectory module is loaded
if (-not (Get-Module -ListAvailable ActiveDirectory)) {
    Write-Error "ActiveDirectory module is not installed."
    exit 1
}

if (-not (Get-Module ActiveDirectory)) {
    Import-Module ActiveDirectory
}

try {
    if ($Type -eq "users") {
        # Fetch all users with all properties
        $data = Get-ADUser -Filter * -Properties *
    }
    else {
        # Fetch all computers with all properties
        $data = Get-ADComputer -Filter * -Properties *
    }

    if ($null -eq $data) {
        Write-Output "[]"
        exit 0
    }

    # Convert to JSON. We select properties carefully to avoid circular references 
    # and deep object nesting that might break ConvertTo-Json or make it too large.
    # We'll use a PSCustomObject to flatten the most common properties if needed, 
    # but for "as many as possible", we'll just try to convert the whole thing.
    
    # AD Objects have a lot of properties. We'll filter out empty ones to save space.
    $results = foreach ($obj in $data) {
        $hash = [ordered]@{ }
        foreach ($prop in $obj.PropertyNames) {
            $val = $obj.$prop
            if ($null -ne $val) {
                # Handle multi-valued attributes by joining them
                if ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
                    $hash[$prop] = $val -join "; "
                }
                else {
                    $hash[$prop] = $val
                }
            }
        }
        [PSCustomObject]$hash
    }

    $results | ConvertTo-Json -Depth 2 -Compress
}
catch {
    Write-Error "Failed to fetch AD data: $_"
    exit 1
}
