function Get-HKLdapBinding {
    <#
    .SYNOPSIS
        Meet unsigned/simple LDAP-binds en ontbrekende channel binding.

    .DESCRIPTION
        Leest Directory Service-events 2889 (unsigned SASL-bind of simple bind, per client) en
        3039 (channel binding ontbreekt, zou geweigerd zijn in enforce-modus, per client) en
        aggregeert die per client-IP en account. Events 2887 en 3041 zijn periodieke 24-uurs
        tellingen zonder per-client detail (geen IP/account) en worden apart teruggegeven als
        dagsamenvatting, niet in de per-client Findings.

        Vereist dat 2889 kan verschijnen: verhoogde LDAP-diagnostiek (zie Get-HKLdapAuditSettings
        / Test-HKAuditConfig, maatregel 'ldap_signing'). Channel binding-events vereisen dat
        LdapEnforceChannelBinding in auditstand staat (maatregel 'ldap_channel_binding').

    .PARAMETER ComputerName
        Host om te meten. Alleen de lokale machine wordt ondersteund.

    .PARAMETER DirectoryServiceStartRecordId
        Laatst gelezen EventRecordID in het Directory Service-log; alleen nieuwere events
        worden gelezen. Weglaten leest alle beschikbare events in het log.

    .OUTPUTS
        PSCustomObject met:
          - ComputerName, CheckedAtUtc
          - Collectors: leesstatus van het Directory Service-log
          - Findings: geaggregeerde per-client bevindingen (ldap_signing uit 2889,
            ldap_channel_binding uit 3039): AccountName, ClientIp, Count, FirstSeenUtc,
            LastSeenUtc
          - SigningDailySummary, ChannelBindingDailySummary: ruwe 24-uurs tellingen uit
            2887/3041 (TimeCreatedUtc, Count), zonder per-client detail
          - LastDirectoryServiceRecordId: hoogste geziene RecordId, voor de volgende
            incrementele run

    .NOTES
        Fase 0. Alleen-lezen. De exacte EventData-veldnamen van 2887/2889/3039/3041 zijn de
        minst zekere aanname in dit project tot nu toe — zie docs/LESSONS.md. Dit als eerste
        valideren tegen een echte DC voor de pilot.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [Nullable[long]]$DirectoryServiceStartRecordId
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKLdapBinding ondersteunt alleen de lokale machine."
    }

    $collectorStatus = [ordered]@{
        DirectoryServiceLog = 'ok'
    }

    try {
        $events = @(Get-HKWinEvent -LogName 'Directory Service' -Id @(2887, 2889, 3039, 3041) -StartRecordId $DirectoryServiceStartRecordId -ComputerName $ComputerName)
    }
    catch {
        Write-Warning "Get-HKLdapBinding: Directory Service-log (2887/2889/3039/3041) kon niet gelezen worden: $_"
        $events = @()
        $collectorStatus.DirectoryServiceLog = 'onbekend'
    }

    # ldap_signing: 2889, per client (unsigned SASL-bind of simple bind).
    $signingRows = @(
        foreach ($e in $events) {
            if ($e.EventId -ne 2889) { continue }

            [pscustomobject]@{
                Measure        = 'ldap_signing'
                AccountName    = $e.EventData['IdentityUser']
                AccountSid     = $null
                ClientFqdn     = $null
                ClientIp       = $e.EventData['Client']
                Target         = $null
                TimeCreatedUtc = $e.TimeCreatedUtc
            }
        }
    )

    # ldap_channel_binding: 3039, per client (channel binding ontbreekt).
    $channelBindingRows = @(
        foreach ($e in $events) {
            if ($e.EventId -ne 3039) { continue }

            [pscustomobject]@{
                Measure        = 'ldap_channel_binding'
                AccountName    = $null
                AccountSid     = $null
                ClientFqdn     = $null
                ClientIp       = $e.EventData['Client']
                Target         = $null
                TimeCreatedUtc = $e.TimeCreatedUtc
            }
        }
    )

    $groupBy = @('Measure', 'AccountName', 'AccountSid', 'ClientFqdn', 'ClientIp', 'Target')
    $rows = @($signingRows) + @($channelBindingRows)

    $findings = [System.Collections.Generic.List[psobject]]::new()
    foreach ($row in @($rows | ConvertTo-HKAggregate -GroupBy $groupBy)) { $findings.Add($row) }

    # 2887/3041: periodieke 24-uurs tellingen, geen per-client detail.
    $signingDailySummary = @(
        foreach ($e in $events) {
            if ($e.EventId -ne 2887) { continue }
            [pscustomobject]@{
                TimeCreatedUtc = $e.TimeCreatedUtc
                Count          = $(if ([string]::IsNullOrWhiteSpace($e.EventData['Count'])) { 0 } else { [int]$e.EventData['Count'] })
            }
        }
    )
    $channelBindingDailySummary = @(
        foreach ($e in $events) {
            if ($e.EventId -ne 3041) { continue }
            [pscustomobject]@{
                TimeCreatedUtc = $e.TimeCreatedUtc
                Count          = $(if ([string]::IsNullOrWhiteSpace($e.EventData['Count'])) { 0 } else { [int]$e.EventData['Count'] })
            }
        }
    )

    $lastRecordId =
        if ($events.Count -gt 0) { ($events | Measure-Object -Property EventRecordId -Maximum).Maximum }
        else { $DirectoryServiceStartRecordId }

    [pscustomobject]@{
        ComputerName                 = $ComputerName
        CheckedAtUtc                 = (Get-Date).ToUniversalTime()
        Collectors                   = [pscustomobject]$collectorStatus
        Findings                     = $findings.ToArray()
        SigningDailySummary          = $signingDailySummary
        ChannelBindingDailySummary   = $channelBindingDailySummary
        LastDirectoryServiceRecordId = $lastRecordId
    }
}
