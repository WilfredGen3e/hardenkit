function Merge-HKFindings {
    <#
    .SYNOPSIS
        Merget findingregels uit meerdere dagbestanden/DC's tot één set per unieke combinatie.

    .DESCRIPTION
        Groepeert op measure + client.fqdn + client.ip + account.name + account.sid + target en
        telt de counts bij elkaar op — niet opnieuw tellen, want elke invoerregel is al een
        geaggregeerde telling uit één dagbestand (zie ConvertTo-HKFindingRecord) — met de
        vroegste firstSeen en de laatste lastSeen over alle bestanden heen.

    .PARAMETER InputObject
        Findingregels in het PRD-JSON-formaat (measure, client, account, target?, isIpOrAlias?,
        count, firstSeen, lastSeen), zoals uit meerdere dagbestanden gelezen en samengevoegd.

    .OUTPUTS
        PSCustomObject[] in hetzelfde formaat, gemerged.

    .NOTES
        Fase 0. Pure functie, geen I/O. firstSeen/lastSeen worden expliciet naar [datetime]
        gecast — niet aangenomen dat ConvertFrom-Json dit al deed (zie docs/LESSONS.md: dat
        gedrag is niet in elke PowerShell-versie gegarandeerd hetzelfde).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyCollection()]
        [psobject[]]$InputObject
    )

    begin {
        $rows = [System.Collections.Generic.List[psobject]]::new()
    }
    process {
        foreach ($row in $InputObject) { $rows.Add($row) }
    }
    end {
        # Handmatige groepering op een samengestelde sleutel i.p.v. Group-Object met geneste
        # calculated properties: betrouwbaarder met $null-velden (bv. account.name bij
        # 'outbound') en makkelijker te doorzien.
        $buckets = [ordered]@{}

        foreach ($row in $rows) {
            $key = @(
                $row.measure
                $row.client.fqdn
                $row.client.ip
                $row.account.name
                $row.account.sid
                $row.target
            ) -join "`u{1}"

            if (-not $buckets.Contains($key)) {
                $buckets[$key] = [System.Collections.Generic.List[psobject]]::new()
            }
            $buckets[$key].Add($row)
        }

        foreach ($key in $buckets.Keys) {
            $group = $buckets[$key]
            $first = $group[0]

            $totalCount = ($group | Measure-Object -Property count -Sum).Sum
            $firstSeenTimes = $group | ForEach-Object { [datetime]$_.firstSeen }
            $lastSeenTimes = $group | ForEach-Object { [datetime]$_.lastSeen }
            $isIpOrAliasRow = $group | Where-Object { $_.PSObject.Properties.Match('isIpOrAlias').Count -gt 0 } | Select-Object -First 1

            $record = [ordered]@{
                measure = $first.measure
                client  = [ordered]@{ fqdn = $first.client.fqdn; ip = $first.client.ip }
                account = [ordered]@{ name = $first.account.name; sid = $first.account.sid }
            }
            if (-not [string]::IsNullOrEmpty($first.target)) { $record['target'] = $first.target }
            if ($isIpOrAliasRow) { $record['isIpOrAlias'] = $isIpOrAliasRow.isIpOrAlias }
            $record['count'] = $totalCount
            $record['firstSeen'] = ($firstSeenTimes | Measure-Object -Minimum).Minimum
            $record['lastSeen'] = ($lastSeenTimes | Measure-Object -Maximum).Maximum

            [pscustomobject]$record
        }
    }
}
