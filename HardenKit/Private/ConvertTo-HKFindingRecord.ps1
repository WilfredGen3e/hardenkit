function ConvertTo-HKFindingRecord {
    <#
    .SYNOPSIS
        Zet een intern geaggregeerde findingregel om naar het JSON-dataformaat uit de PRD.

    .DESCRIPTION
        Pure mapping-stap: de collectors (Get-HKNtlmUsage, Get-HKLdapBinding, en later
        Get-HKKerberos/Get-HKDomainHealth) werken intern met platte rijen
        (Measure/AccountName/AccountSid/ClientFqdn/ClientIp/Target/Count/FirstSeenUtc/
        LastSeenUtc, optioneel IsIpOrAlias). Export-HKData zet die via deze functie om naar de
        geneste JSON-vorm uit de PRD (client.fqdn/ip, account.name/sid, ISO 8601 UTC-tijden).

    .PARAMETER InputObject
        Eén interne findingregel.

    .OUTPUTS
        PSCustomObject met measure, client, account, target (alleen aanwezig als niet leeg),
        isIpOrAlias (alleen aanwezig als de regel dat veld heeft), count, firstSeen, lastSeen.

    .NOTES
        Fase 0. Pure functie, geen I/O.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject]$InputObject
    )

    process {
        $record = [ordered]@{
            measure = $InputObject.Measure
            client  = [ordered]@{
                fqdn = $InputObject.ClientFqdn
                ip   = $InputObject.ClientIp
            }
            account = [ordered]@{
                name = $InputObject.AccountName
                sid  = $InputObject.AccountSid
            }
            count     = $InputObject.Count
            # .ToUniversalTime() hier expliciet, niet aannemen dat de invoer al Kind=Utc heeft:
            # .ToString('...Z') plakt een letterlijke 'Z' achter de waarde, ongeacht de Kind.
            firstSeen = $InputObject.FirstSeenUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            lastSeen  = $InputObject.LastSeenUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        }

        if (-not [string]::IsNullOrEmpty($InputObject.Target)) {
            $record['target'] = $InputObject.Target
        }

        if ($InputObject.PSObject.Properties.Match('IsIpOrAlias').Count -gt 0) {
            $record['isIpOrAlias'] = $InputObject.IsIpOrAlias
        }

        [pscustomobject]$record
    }
}
