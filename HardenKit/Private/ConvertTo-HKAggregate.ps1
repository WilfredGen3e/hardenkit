function ConvertTo-HKAggregate {
    <#
    .SYNOPSIS
        Aggregeert losse findingregels tot het PRD-dataformaat: telling + eerste/laatste keer
        gezien per unieke combinatie van sleutelvelden.

    .DESCRIPTION
        Generieke, pure aggregatiestap die door elke eventlog-collector hergebruikt kan worden
        (zie docs/LESSONS.md). Groepeert de invoer op de kolommen in -GroupBy en berekent per
        groep Count, FirstSeenUtc en LastSeenUtc op basis van TimeCreatedUtc. De GroupBy-
        kolomwaarden van de eerste regel in elke groep worden overgenomen in het resultaat.

    .PARAMETER InputObject
        Rijen met minimaal een TimeCreatedUtc-property ([datetime]) en de kolommen in -GroupBy.

    .PARAMETER GroupBy
        Namen van de properties om op te groeperen (bv. Measure, AccountName, AccountSid,
        ClientFqdn, ClientIp, Target).

    .OUTPUTS
        PSCustomObject[] met de GroupBy-kolommen plus Count ([int]), FirstSeenUtc ([datetime])
        en LastSeenUtc ([datetime]).

    .NOTES
        Fase 0. Pure functie, geen I/O. Gebruik @(...) rond de aanroep (zie docs/LESSONS.md).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyCollection()]
        [psobject[]]$InputObject,

        [Parameter(Mandatory)]
        [string[]]$GroupBy
    )

    begin {
        $rows = [System.Collections.Generic.List[psobject]]::new()
    }
    process {
        foreach ($row in $InputObject) { $rows.Add($row) }
    }
    end {
        $groups = $rows | Group-Object -Property $GroupBy

        foreach ($group in $groups) {
            $first = $group.Group[0]
            $times = $group.Group | ForEach-Object { $_.TimeCreatedUtc }

            $result = [ordered]@{}
            foreach ($key in $GroupBy) { $result[$key] = $first.$key }
            $result['Count'] = $group.Count
            $result['FirstSeenUtc'] = ($times | Measure-Object -Minimum).Minimum
            $result['LastSeenUtc'] = ($times | Measure-Object -Maximum).Maximum

            [pscustomobject]$result
        }
    }
}
