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
        Fase 0. De waarde van 'Inclusion Setting' is Engelstalig op een Engelstalige Windows-
        installatie; op een Nederlandstalige DC kan deze tekst afwijken. Nog te verifiëren op
        een echte DC (zie open vragen in CLAUDE.md).
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

        $setting = $row.'Inclusion Setting'
        [pscustomobject]@{
            Success = $setting -in @('Success', 'Success and Failure')
            Failure = $setting -in @('Failure', 'Success and Failure')
        }
    }
}
