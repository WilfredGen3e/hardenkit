function Get-HKOutbound {
    <#
    .SYNOPSIS
        Momentopname van uitgaande verbindingen vanaf de DC, met proces en DNS-naam.

    .DESCRIPTION
        Legt uitgaande verbindingen vast (proces + bestemming, via Get-NetTCPConnection en de
        lokale DNS-clientcache) als basis voor een allowlist-voorstel voor uitgaand verkeer van
        DC's. Dit is een momentopname, geen incrementele eventlog-lezing: elke aanroep legt de
        actieve verbindingen op dát moment vast; Export-HKData roept dit dagelijks aan, dus
        herhaalde momentopnames over meerdere dagen laten samen zien welk uitgaand verkeer
        structureel is.

        Bedoeld om te onderbouwen dat internettoegang van DC's dicht kan zonder noodzakelijk
        verkeer te breken (zie PRD, uitgangspunt 5). Geen event 5156: dat is optioneel en alleen
        tijdelijk in te zetten (zie PRD), en wordt in fase 0 niet door deze functie gelezen.

    .PARAMETER ComputerName
        Host om te meten. Alleen de lokale machine wordt ondersteund.

    .OUTPUTS
        PSCustomObject met:
          - ComputerName, CheckedAtUtc
          - Collectors: leesstatus van de verbindingen-bron
          - Findings: geaggregeerd per proces en bestemming (Measure='outbound', Target=proces-
            naam, client.ip/client.fqdn=bestemming — AccountName/AccountSid zijn hier niet van
            toepassing en altijd leeg, want er is geen gebruikersaccount bij uitgaand DC-verkeer)

    .NOTES
        Fase 0. Alleen-lezen.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKOutbound ondersteunt alleen de lokale machine."
    }

    $collectorStatus = [ordered]@{
        Connections = 'ok'
    }

    try {
        $rawRows = @(Get-HKOutboundConnections -ComputerName $ComputerName)
    }
    catch {
        Write-Warning "Get-HKOutbound: uitgaande verbindingen konden niet gelezen worden: $_"
        $rawRows = @()
        $collectorStatus.Connections = 'onbekend'
    }

    $groupBy = @('Measure', 'AccountName', 'AccountSid', 'ClientFqdn', 'ClientIp', 'Target')
    $findings = [System.Collections.Generic.List[psobject]]::new()
    foreach ($row in @($rawRows | ConvertTo-HKAggregate -GroupBy $groupBy)) { $findings.Add($row) }

    [pscustomobject]@{
        ComputerName = $ComputerName
        CheckedAtUtc = (Get-Date).ToUniversalTime()
        Collectors   = [pscustomobject]$collectorStatus
        Findings     = $findings.ToArray()
    }
}
