function ConvertFrom-HKAuditPolicyCsv {
    <#
    .SYNOPSIS
        Parsed de CSV-uitvoer van 'auditpol /get /subcategory:"<naam>" /r' naar succes/faal-vlaggen.

    .DESCRIPTION
        Pure parsing-stap, los van het aanroepen van auditpol.exe zelf (zie Get-HKAuditPolicy),
        zodat de parsing-logica onafhankelijk van Windows getest kan worden.

    .PARAMETER InputObject
        De regels (string[]) die auditpol.exe teruggeeft voor één subcategorie, inclusief
        CSV-header.

    .OUTPUTS
        PSCustomObject met Success ([bool]) en Failure ([bool]).

    .NOTES
        Fase 0. Gebruikt bij voorkeur de numerieke kolom 'Setting Value'; de tekst van
        'Inclusion Setting' is gelokaliseerd en wordt alleen als terugval gebruikt (Engels en
        Nederlands). Of 'Setting Value' in de /r-uitvoer zit en de exacte Nederlandse teksten
        zijn nog te verifiëren op een echte DC (zie pilot-testlijst in docs/LESSONS.md).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$InputObject
    )

    begin {
        $lines = [System.Collections.Generic.List[string]]::new()
    }
    process {
        foreach ($line in $InputObject) { $lines.Add($line) }
    }
    end {
        $row = $lines | ConvertFrom-Csv | Select-Object -Last 1
        if (-not $row) {
            throw "Geen auditpol-uitvoer om te parsen."
        }

        # Voorkeur: de numerieke 'Setting Value' (bitmask 1 = succes, 2 = fout), die is
        # taalonafhankelijk. Valt terug op de tekst van 'Inclusion Setting' (Engels/Nederlands).
        $settingValue = $row.PSObject.Properties['Setting Value']
        if ($settingValue -and "$($settingValue.Value)" -match '^\d+$') {
            $value = [int]$settingValue.Value
            return [pscustomobject]@{
                Success = ($value -band 1) -ne 0
                Failure = ($value -band 2) -ne 0
            }
        }

        $setting = "$($row.'Inclusion Setting')".Trim()
        $known = @{
            'Success'             = @($true,  $false)
            'Failure'             = @($false, $true)
            'Success and Failure' = @($true,  $true)
            'No Auditing'         = @($false, $false)
            'Geslaagd'            = @($true,  $false)
            'Mislukt'             = @($false, $true)
            'Geslaagd en mislukt' = @($true,  $true)
            'Geen controle'       = @($false, $false)
        }
        if (-not $known.ContainsKey($setting)) {
            # Onbekende tekst niet als "uit" interpreteren: dan wordt het NietVoldaan i.p.v. Onbekend.
            throw "Onbekende auditpol-waarde '$setting' (taal niet herkend)."
        }

        [pscustomobject]@{
            Success = $known[$setting][0]
            Failure = $known[$setting][1]
        }
    }
}
