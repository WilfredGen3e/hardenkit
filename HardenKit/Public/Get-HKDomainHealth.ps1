function Get-HKDomainHealth {
    <#
    .SYNOPSIS
        Meet Netlogon-weigeringen, lockouts, onbekende subnetten, tijdsafwijking en replicatiefouten.

    .DESCRIPTION
        Combineert drie logs in één collector:
          - System: 5827/5828 (Netlogon secure channel geweigerd, per machine-account — "al
            stuk"), 5816-5819 (Netlogon-verzadiging door NTLM-belasting), 5807 (onbekende
            subnetten — periodieke 24-uurs telling, zoals 2887/3041 in Get-HKLdapBinding; echte
            per-client IP-detail staat alleen in netlogon.log, niet in het eventlog, en wordt in
            fase 0 niet geparsed), 29/36/50 (W32Time: tijdbron onbereikbaar/ongeldig resp.
            tijdsafwijking boven de drempel).
          - Security: 4740 (account lockout) en 4625 (mislukte logon), samen als 'lockouts'.
          - Directory Service: 1311/1865/2042 (replicatiefouten; PRD noemt deze als voorbeeld
            ("o.a."), DFSR-equivalenten worden in fase 0 niet gelezen).
        Netlogon-verzadiging, tijdsafwijking en replicatie hebben geen bekend betrouwbaar
        per-client veld en worden daarom als losse voorvallen geteld (één rij per maatregel na
        aggregatie), niet per account/client.

        Let op: Security en Directory Service worden ook door andere collectors gelezen
        (Get-HKNtlmUsage/Get-HKKerberos resp. Get-HKLdapBinding), maar voor andere event-ID's.
        Deze functie gebruikt daarom haar eigen RecordId-parameters; Export-HKData bewaart ze
        onder eigen sleutels in het statusbestand (zie docs/LESSONS.md).

    .PARAMETER ComputerName
        Host om te meten. Alleen de lokale machine wordt ondersteund.

    .PARAMETER SecurityStartRecordId
        Laatst gelezen EventRecordID in het Security-log (4740/4625), voor déze collector.

    .PARAMETER SystemStartRecordId
        Laatst gelezen EventRecordID in het System-log (5807/5816-5819/5827/5828/29/36/50).

    .PARAMETER DirectoryServiceStartRecordId
        Laatst gelezen EventRecordID in het Directory Service-log (1311/1865/2042), voor déze
        collector.

    .OUTPUTS
        PSCustomObject met:
          - ComputerName, CheckedAtUtc
          - Collectors: leesstatus per log (SecurityLog, SystemLog, DirectoryServiceLog)
          - Findings: geaggregeerde bevindingen (netlogon_secure_channel, netlogon_saturation,
            lockouts, time_sync, replication)
          - UnknownSubnetsDailySummary: ruwe 24-uurs tellingen uit 5807 (TimeCreatedUtc, Count)
          - LastSecurityRecordId, LastSystemRecordId, LastDirectoryServiceRecordId

    .NOTES
        Fase 0. Alleen-lezen. EventData-veldnamen van 5827/5828 (MachineAccount) en de aanname
        dat 5816-5819 geen bruikbaar per-client veld hebben, zijn niet geverifieerd — zie de
        pilot-testlijst in docs/LESSONS.md. 4740/4625/1311/1865/2042 zijn beter gedocumenteerd.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [Nullable[long]]$SecurityStartRecordId,
        [Nullable[long]]$SystemStartRecordId,
        [Nullable[long]]$DirectoryServiceStartRecordId
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKDomainHealth ondersteunt alleen de lokale machine."
    }

    $collectorStatus = [ordered]@{
        SecurityLog         = 'ok'
        SystemLog           = 'ok'
        DirectoryServiceLog = 'ok'
    }

    try {
        $securityEvents = @(Get-HKWinEvent -LogName 'Security' -Id @(4740, 4625) -StartRecordId $SecurityStartRecordId -ComputerName $ComputerName)
    }
    catch {
        Write-Warning "Get-HKDomainHealth: Security-log (4740/4625) kon niet gelezen worden: $_"
        $securityEvents = @()
        $collectorStatus.SecurityLog = 'onbekend'
    }

    try {
        $systemEvents = @(Get-HKWinEvent -LogName 'System' -Id @(5807, 5816, 5817, 5818, 5819, 5827, 5828, 29, 36, 50) -StartRecordId $SystemStartRecordId -ComputerName $ComputerName)
    }
    catch {
        Write-Warning "Get-HKDomainHealth: System-log kon niet gelezen worden: $_"
        $systemEvents = @()
        $collectorStatus.SystemLog = 'onbekend'
    }

    try {
        $directoryServiceEvents = @(Get-HKWinEvent -LogName 'Directory Service' -Id @(1311, 1865, 2042) -StartRecordId $DirectoryServiceStartRecordId -ComputerName $ComputerName)
    }
    catch {
        Write-Warning "Get-HKDomainHealth: Directory Service-log (1311/1865/2042) kon niet gelezen worden: $_"
        $directoryServiceEvents = @()
        $collectorStatus.DirectoryServiceLog = 'onbekend'
    }

    # netlogon_secure_channel: 5827/5828, per machine-account. "Al stuk": dit gebeurt nu al.
    $netlogonSecureChannelRows = @(
        foreach ($e in $systemEvents) {
            if ($e.EventId -notin @(5827, 5828)) { continue }
            [pscustomobject]@{
                Measure        = 'netlogon_secure_channel'
                AccountName    = $e.EventData['MachineAccount']
                AccountSid     = $null
                ClientFqdn     = $null
                ClientIp       = $null
                Target         = $null
                TimeCreatedUtc = $e.TimeCreatedUtc
            }
        }
    )

    # netlogon_saturation: 5816-5819, geen bekend per-client veld, dus als los voorval geteld.
    $netlogonSaturationRows = @(
        foreach ($e in $systemEvents) {
            if ($e.EventId -notin @(5816, 5817, 5818, 5819)) { continue }
            [pscustomobject]@{
                Measure        = 'netlogon_saturation'
                AccountName    = $null
                AccountSid     = $null
                ClientFqdn     = $null
                ClientIp       = $null
                Target         = $null
                TimeCreatedUtc = $e.TimeCreatedUtc
            }
        }
    )

    # time_sync: W32Time 29 (bron onbereikbaar/ongeldig), 36, 50 (afwijking boven drempel).
    $timeSyncRows = @(
        foreach ($e in $systemEvents) {
            if ($e.EventId -notin @(29, 36, 50)) { continue }
            [pscustomobject]@{
                Measure        = 'time_sync'
                AccountName    = $null
                AccountSid     = $null
                ClientFqdn     = $null
                ClientIp       = $null
                Target         = $null
                TimeCreatedUtc = $e.TimeCreatedUtc
            }
        }
    )

    # lockouts: 4740 (lockout, met CallerComputerName als bron) + 4625 (mislukte logon).
    $lockoutRows = @(
        foreach ($e in $securityEvents) {
            if ($e.EventId -eq 4740) {
                [pscustomobject]@{
                    Measure        = 'lockouts'
                    AccountName    = $e.EventData['TargetUserName']
                    AccountSid     = $e.EventData['TargetSid']
                    ClientFqdn     = $e.EventData['CallerComputerName']
                    ClientIp       = $null
                    Target         = $null
                    TimeCreatedUtc = $e.TimeCreatedUtc
                }
            }
            elseif ($e.EventId -eq 4625) {
                [pscustomobject]@{
                    Measure        = 'lockouts'
                    AccountName    = $e.EventData['TargetUserName']
                    AccountSid     = $e.EventData['TargetUserSid']
                    ClientFqdn     = $e.EventData['WorkstationName']
                    ClientIp       = $e.EventData['IpAddress']
                    Target         = $null
                    TimeCreatedUtc = $e.TimeCreatedUtc
                }
            }
        }
    )

    # replication: Directory Service 1311/1865/2042, geen bekend betrouwbaar veld, los geteld.
    $replicationRows = @(
        foreach ($e in $directoryServiceEvents) {
            if ($e.EventId -notin @(1311, 1865, 2042)) { continue }
            [pscustomobject]@{
                Measure        = 'replication'
                AccountName    = $null
                AccountSid     = $null
                ClientFqdn     = $null
                ClientIp       = $null
                Target         = $null
                TimeCreatedUtc = $e.TimeCreatedUtc
            }
        }
    )

    $groupBy = @('Measure', 'AccountName', 'AccountSid', 'ClientFqdn', 'ClientIp', 'Target')
    $rows = @($netlogonSecureChannelRows) + @($netlogonSaturationRows) + @($timeSyncRows) + @($lockoutRows) + @($replicationRows)

    $findings = [System.Collections.Generic.List[psobject]]::new()
    foreach ($row in @($rows | ConvertTo-HKAggregate -GroupBy $groupBy)) { $findings.Add($row) }

    # 5807: periodieke 24-uurs telling, geen per-client detail (zie boven).
    $unknownSubnetsDailySummary = @(
        foreach ($e in $systemEvents) {
            if ($e.EventId -ne 5807) { continue }
            [pscustomobject]@{
                TimeCreatedUtc = $e.TimeCreatedUtc
                Count          = $(if ([string]::IsNullOrWhiteSpace($e.EventData['Count'])) { 0 } else { [int]$e.EventData['Count'] })
            }
        }
    )

    $lastSecurityRecordId =
        if ($securityEvents.Count -gt 0) { ($securityEvents | Measure-Object -Property EventRecordId -Maximum).Maximum }
        else { $SecurityStartRecordId }
    $lastSystemRecordId =
        if ($systemEvents.Count -gt 0) { ($systemEvents | Measure-Object -Property EventRecordId -Maximum).Maximum }
        else { $SystemStartRecordId }
    $lastDirectoryServiceRecordId =
        if ($directoryServiceEvents.Count -gt 0) { ($directoryServiceEvents | Measure-Object -Property EventRecordId -Maximum).Maximum }
        else { $DirectoryServiceStartRecordId }

    [pscustomobject]@{
        ComputerName                 = $ComputerName
        CheckedAtUtc                 = (Get-Date).ToUniversalTime()
        Collectors                   = [pscustomobject]$collectorStatus
        Findings                     = $findings.ToArray()
        UnknownSubnetsDailySummary   = $unknownSubnetsDailySummary
        LastSecurityRecordId         = $lastSecurityRecordId
        LastSystemRecordId           = $lastSystemRecordId
        LastDirectoryServiceRecordId = $lastDirectoryServiceRecordId
    }
}
