function ConvertFrom-HKSetspnOutput {
    <#
    .SYNOPSIS
        Parsed de tekstuitvoer van 'setspn -X' naar een lijst van dubbele SPN's met accounts.

    .DESCRIPTION
        Pure parsing-stap, los van het aanroepen van setspn.exe zelf (zie Get-HKDuplicateSpn),
        zodat de parsing-logica onafhankelijk van Windows getest kan worden. Een niet-ingesprongen
        regel die geen bekende boilerplate is ("Checking domain...", "Processing entry N",
        "found N group...", "operation completed...") wordt als SPN-naam gezien (zonder het
        achtervoegsel "is registered on these accounts:"); de ingesprongen regels erna zijn de
        accounts (DN's) die die SPN delen.

    .PARAMETER InputObject
        De regels (string[]) die setspn.exe -X teruggeeft.

    .OUTPUTS
        PSCustomObject[] met Spn ([string]) en Accounts ([string[]]). Leeg als er geen dubbele
        SPN's zijn.

    .NOTES
        Fase 0. setspn.exe-uitvoer is Engelstalig; net als bij auditpol (zie
        ConvertFrom-HKAuditPolicyCsv) nog te verifiëren op een Nederlandstalige DC.
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
        # Hoofdletterongevoelig: echte uitvoer (Server 2022) is "found 0 group of duplicate SPNs."
        # met kleine letter, plus een "Processing entry N"-regel per verwerkte batch.
        $boilerplatePattern = '^(Checking domain|Processing entry|Found \d+ group|operation completed)'
    }
    process {
        foreach ($line in $InputObject) { $lines.Add($line) }
    }
    end {
        $results = [System.Collections.Generic.List[pscustomobject]]::new()
        $currentSpn = $null
        $currentAccounts = [System.Collections.Generic.List[string]]::new()

        foreach ($raw in $lines) {
            if ([string]::IsNullOrWhiteSpace($raw)) { continue }

            $trimmed = $raw.Trim()
            if ($trimmed -match $boilerplatePattern) { continue }

            if ($raw -match '^\s') {
                # Ingesprongen regel: account-DN onder de huidige SPN.
                if ($currentSpn) { $currentAccounts.Add($trimmed) }
                continue
            }

            # Niet-ingesprongen, niet-boilerplate regel: nieuwe SPN.
            if ($currentSpn) {
                $results.Add([pscustomobject]@{ Spn = $currentSpn; Accounts = $currentAccounts.ToArray() })
            }
            # setspn zet "<spn> is registered on these accounts:" boven de accountregels.
            $currentSpn = $trimmed -replace '\s+is registered on these accounts:?$', ''
            $currentAccounts = [System.Collections.Generic.List[string]]::new()
        }

        if ($currentSpn) {
            $results.Add([pscustomobject]@{ Spn = $currentSpn; Accounts = $currentAccounts.ToArray() })
        }

        # Geen comma-trick hier: die geeft binnen Pester's InModuleScope een dubbel-geneste
        # array (bevestigd met een losse repro). Gewoon losse objecten streamen; de aanroeper
        # (Get-HKDuplicateSpn) wrapt zelf met @(...) voor consistente array-vorm bij 0/1/N
        # resultaten.
        $results.ToArray()
    }
}
