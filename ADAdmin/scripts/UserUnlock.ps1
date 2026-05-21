<#
.SYNOPSIS
    Ein Skript zum Suchen, Auflisten und Entsperren von gesperrten Active Directory-Benutzern.

.DESCRIPTION
    1. Sucht nach allen Benutzern mit dem Status 'Gesperrt' (LockedOut).
    2. Zeigt die Benutzer in einer nummerierten Liste (Index) an.
    3. Fragt den Administrator nach einer Indexnummer.
    4. Entsperrt das ausgewählte Benutzerkonto.

.NOTES
    Erfordert das Active Directory PowerShell-Modul und entsprechende Berechtigungen.
#>

# Sicherstellen, dass das Active Directory-Modul geladen ist
if (!(Get-Module -ListAvailable ActiveDirectory)) {
    Write-Error "Das Active Directory-Modul ist erforderlich. Bitte installieren Sie RSAT."
    return
}

try {
    # 1. Alle gesperrten Benutzer abrufen
    # Wir erzwingen hier ein Array mit @(), falls nur ein einzelner Benutzer gefunden wird.
    Write-Host "Suche nach gesperrten Konten..." -ForegroundColor Gray
    
    $lockedAccounts = @(Search-ADAccount -LockedOut -UsersOnly)
    
    if ($lockedAccounts.Count -eq 0) {
        Write-Host "Keine gesperrten Benutzer gefunden." -ForegroundColor Cyan
        return
    }

    # Wir holen uns die detaillierten Informationen für die Anzeige
    $lockedUsers = @()
    foreach ($account in $lockedAccounts) {
        $userDetails = Get-ADUser -Identity $account.DistinguishedName -Properties DisplayName, SamAccountName
        $lockedUsers += [PSCustomObject]@{
            DisplayName       = $userDetails.DisplayName
            SamAccountName    = $userDetails.SamAccountName
            DistinguishedName = $userDetails.DistinguishedName
        }
    }

    # 2. Liste mit Index anzeigen
    Write-Host "`n--- Gesperrte Benutzerkonten ($($lockedUsers.Count)) ---" -ForegroundColor Yellow
    for ($i = 0; $i -lt $lockedUsers.Count; $i++) {
        $user = $lockedUsers[$i]
        $name = if ($user.DisplayName) { $user.DisplayName } else { "Kein Anzeigename" }
        Write-Host ("[{0}] {1} ({2})" -f $i, $name, $user.SamAccountName)
    }

    # 3. Index abfragen
    Write-Host ""
    $inputIndex = Read-Host "Geben Sie die Indexnummer des zu entsperrenden Benutzers ein (oder 'q' zum Beenden)"

    if ($inputIndex -eq 'q') {
        Write-Host "Programm beendet."
        return
    }

    # Eingabe validieren
    if ($inputIndex -match '^\d+$' -and [int]$inputIndex -ge 0 -and [int]$inputIndex -lt $lockedUsers.Count) {
        $targetUser = $lockedUsers[[int]$inputIndex]
        
        # 4. Benutzer entsperren
        Unlock-ADAccount -Identity $targetUser.DistinguishedName
        
        Write-Host "Konto erfolgreich entsperrt: $($targetUser.DisplayName) ($($targetUser.SamAccountName))" -ForegroundColor Green
    }
    else {
        Write-Host "Ungültige Index-Auswahl." -ForegroundColor Red
    }

}
catch {
    Write-Error "Ein Fehler ist aufgetreten: $($_.Exception.Message)"
}