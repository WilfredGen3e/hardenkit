function Get-HKNtlmUsage {
    <#
    .SYNOPSIS
        Meet NTLMv1/LM-gebruik en NTLM-authenticatie, inclusief NTLM naar IP of alias.

    .DESCRIPTION
        Leest Security-event 4624 (LmPackageName) voor NTLMv1/LM, Security-event 4776 voor
        NTLM-credentialvalidaties, en NTLM/Operational-event 8004 voor NTLM-gebruik in het
        domein (met een classificatie of het doel een IP-adres of alias is in plaats van een
        FQDN — basis voor de PRD-correlatieregel "NTLM naar IP of alias"). Aggregeert per
        maatregel, account, client en doel tot telling + eerste/laatste keer gezien (UTC).
        Leest incrementeel via StartRecordId; gedeeltelijke uitval van één bron (log niet
        leesbaar, auditing uit) resulteert in status 'onbekend' voor die bron, niet in een
        afgebroken run.

    .PARAMETER ComputerName
        Host om te meten. Alleen de lokale machine wordt ondersteund.

    .PARAMETER SecurityStartRecordId
        Laatst gelezen EventRecordID in het Security-log (voor 4624/4776); alleen nieuwere
        events worden gelezen. Weglaten leest alle beschikbare events in het log.

    .PARAMETER NtlmOperationalStartRecordId
        Laatst gelezen EventRecordID in het NTLM/Operational-log (voor 8004).

    .OUTPUTS
        PSCustomObject met:
          - ComputerName, CheckedAtUtc
          - Collectors: leesstatus per log (SecurityLog, NtlmOperationalLog)
          - Findings: geaggregeerde NTLM-bevindingen (Measure, AccountName, AccountSid,
            ClientFqdn, ClientIp, Target, IsIpOrAlias (alleen bij ntlm_8004), Count,
            FirstSeenUtc, LastSeenUtc)
          - LastSecurityRecordId, LastNtlmOperationalRecordId: hoogste geziene RecordId per log,
            voor de aanroeper om te bewaren voor de volgende incrementele run

    .NOTES
        Fase 0. Alleen-lezen. Vereist dat logon-auditing (4624), Audit Credential Validation
        (4776) en NTLM-audit in het domein (8004) aanstaan — zie Test-HKAuditConfig. De exacte
        EventData-veldnamen van vooral event 8004 zijn gebaseerd op publieke documentatie, nog
        niet geverifieerd tegen een echte DC (zie docs/LESSONS.md).
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [Nullable[long]]$SecurityStartRecordId,
        [Nullable[long]]$NtlmOperationalStartRecordId
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKNtlmUsage ondersteunt alleen de lokale machine."
    }

    $collectorStatus = [ordered]@{
        SecurityLog        = 'ok'
        NtlmOperationalLog = 'ok'
    }

    try {
        $securityEvents = @(Get-HKWinEvent -LogName 'Security' -Id @(4624, 4776) -StartRecordId $SecurityStartRecordId -ComputerName $ComputerName)
    }
    catch {
        Write-Warning "Get-HKNtlmUsage: Security-log (4624/4776) kon niet gelezen worden: $_"
        $securityEvents = @()
        $collectorStatus.SecurityLog = 'onbekend'
    }

    try {
        $ntlmOperationalEvents = @(Get-HKWinEvent -LogName 'Microsoft-Windows-NTLM/Operational' -Id 8004 -StartRecordId $NtlmOperationalStartRecordId -ComputerName $ComputerName)
    }
    catch {
        Write-Warning "Get-HKNtlmUsage: NTLM/Operational-log (8004) kon niet gelezen worden: $_"
        $ntlmOperationalEvents = @()
        $collectorStatus.NtlmOperationalLog = 'onbekend'
    }

    # ntlmv1: 4624 met AuthenticationPackageName=NTLM en LmPackageName='NTLM V1'.
    $ntlmv1Rows = @(
        foreach ($e in $securityEvents) {
            if ($e.EventId -ne 4624) { continue }
            if ($e.EventData['AuthenticationPackageName'] -ne 'NTLM') { continue }
            if ($e.EventData['LmPackageName'] -ne 'NTLM V1') { continue }

            [pscustomobject]@{
                Measure        = 'ntlmv1'
                AccountName    = $e.EventData['TargetUserName']
                AccountSid     = $e.EventData['TargetUserSid']
                ClientFqdn     = $e.EventData['WorkstationName']
                ClientIp       = $e.EventData['IpAddress']
                Target         = $null
                TimeCreatedUtc = $e.TimeCreatedUtc
            }
        }
    )

    # ntlm_4776: Credential Validation is altijd NTLM (het event bestaat niet voor Kerberos).
    $ntlm4776Rows = @(
        foreach ($e in $securityEvents) {
            if ($e.EventId -ne 4776) { continue }

            [pscustomobject]@{
                Measure        = 'ntlm_4776'
                AccountName    = $e.EventData['TargetUserName']
                AccountSid     = $null
                ClientFqdn     = $e.EventData['Workstation']
                ClientIp       = $null
                Target         = $null
                TimeCreatedUtc = $e.TimeCreatedUtc
            }
        }
    )

    # ntlm_8004: NTLM-gebruik in het domein, met IP/alias-classificatie van het doel.
    $ntlm8004Rows = @(
        foreach ($e in $ntlmOperationalEvents) {
            $target = $e.EventData['ServerName']

            [pscustomobject]@{
                Measure        = 'ntlm_8004'
                AccountName    = $e.EventData['UserName']
                AccountSid     = $null
                ClientFqdn     = $e.EventData['Workstation']
                ClientIp       = $null
                Target         = $target
                IsIpOrAlias    = Test-HKIsIpOrAlias -Target $target
                TimeCreatedUtc = $e.TimeCreatedUtc
            }
        }
    )

    $logonGroupBy = @('Measure', 'AccountName', 'AccountSid', 'ClientFqdn', 'ClientIp', 'Target')
    $ntlm8004GroupBy = $logonGroupBy + 'IsIpOrAlias'

    $findings = [System.Collections.Generic.List[psobject]]::new()
    $logonRows = @($ntlmv1Rows) + @($ntlm4776Rows)
    foreach ($row in @($logonRows | ConvertTo-HKAggregate -GroupBy $logonGroupBy)) { $findings.Add($row) }
    foreach ($row in @($ntlm8004Rows | ConvertTo-HKAggregate -GroupBy $ntlm8004GroupBy)) { $findings.Add($row) }

    $lastSecurityRecordId = if ($securityEvents.Count -gt 0) { ($securityEvents | Measure-Object -Property EventRecordId -Maximum).Maximum } else { $SecurityStartRecordId }
    $lastNtlmOperationalRecordId = if ($ntlmOperationalEvents.Count -gt 0) { ($ntlmOperationalEvents | Measure-Object -Property EventRecordId -Maximum).Maximum } else { $NtlmOperationalStartRecordId }

    [pscustomobject]@{
        ComputerName                = $ComputerName
        CheckedAtUtc                = (Get-Date).ToUniversalTime()
        Collectors                  = [pscustomobject]$collectorStatus
        Findings                    = $findings.ToArray()
        LastSecurityRecordId        = $lastSecurityRecordId
        LastNtlmOperationalRecordId = $lastNtlmOperationalRecordId
    }
}
