function Get-HKAuditPolicy {
    <#
    .SYNOPSIS
        Leest het succes/faal-auditniveau van de auditpol-subcategorieën die HardenKit nodig heeft.

    .DESCRIPTION
        Roept 'auditpol /get /subcategory:"<naam>" /r' aan voor elke benodigde subcategorie en
        parsed de CSV-uitvoer via ConvertFrom-HKAuditPolicyCsv. Alleen-lezen; wijzigt geen
        auditinstellingen.

    .PARAMETER ComputerName
        Host om te bevragen. Alleen de lokale machine wordt ondersteund: auditpol.exe heeft
        geen betrouwbare remote-optie.

    .PARAMETER Subcategory
        Auditpol-subcategorieën om te lezen. Standaard de subcategorieën die de fase 0-
        collectors nodig hebben.

    .OUTPUTS
        Hashtable, sleutel = subcategorienaam, waarde = PSCustomObject met Success/Failure.

    .NOTES
        Fase 0. Alleen-lezen. Vereist auditpol.exe (Windows).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,

        [string[]]$Subcategory = @(
            'Logon',
            'Credential Validation',
            'Kerberos Authentication Service',
            'Kerberos Service Ticket Operations'
        )
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKAuditPolicy ondersteunt alleen de lokale machine (auditpol /r heeft geen betrouwbare remote-optie)."
    }

    # Subcategorienamen zijn gelokaliseerd ("Logon" heet op een Nederlandstalige Windows
    # "Aanmelden" en geeft dan auditpol-fout 0x57); de GUID's zijn taalonafhankelijk. De
    # Engelse naam blijft de sleutel in het resultaat.
    $subcategoryGuid = @{
        'Logon'                              = '{0CCE9215-69AE-11D9-BED3-505054503030}'
        'Credential Validation'              = '{0CCE923F-69AE-11D9-BED3-505054503030}'
        'Kerberos Service Ticket Operations' = '{0CCE9240-69AE-11D9-BED3-505054503030}'
        'Kerberos Authentication Service'    = '{0CCE9242-69AE-11D9-BED3-505054503030}'
    }

    $result = @{}

    foreach ($name in $Subcategory) {
        $target = if ($subcategoryGuid.ContainsKey($name)) { $subcategoryGuid[$name] } else { $name }
        $csv = & auditpol.exe /get /subcategory:"$target" /r 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "auditpol.exe gaf exitcode $LASTEXITCODE voor subcategorie '$name': $csv"
        }

        $result[$name] = $csv | ConvertFrom-HKAuditPolicyCsv
    }

    $result
}
