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
        Fase 0. De /r-uitvoer heeft geen numerieke kolom (bevestigd op Server 2022 EN: alleen
        Machine Name, Policy Target, Subcategory, Subcategory GUID, Inclusion Setting,
        Exclusion Setting), dus de gelokaliseerde tekst van 'Inclusion Setting' is de enige bron.
        Engelse teksten bevestigd; de Nederlandse teksten zijn nog te verifiëren (zie
        pilot-testlijst in docs/LESSONS.md).
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

        # 'Inclusion Setting' op naam; terugval op de 5e kolom voor het geval de kopregel op een
        # anderstalige Windows ook vertaald is (kolomvolgorde is vast).
        $column = $row.PSObject.Properties['Inclusion Setting']
        if (-not $column) { $column = @($row.PSObject.Properties)[4] }
        $setting = if ($column) { "$($column.Value)".Trim() } else { '' }
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
