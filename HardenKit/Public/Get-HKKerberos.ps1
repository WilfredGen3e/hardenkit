function Get-HKKerberos {
    <#
    .SYNOPSIS
        Meet Kerberos RC4/DES-gebruik, ontbrekende SPN's, dubbele SPN's en zwakke certificaatmapping.

    .DESCRIPTION
        Leest Security-events 4768 (TGT) en 4769 (service ticket) en meet zwakke
        Kerberos-encryptie (RC4: 0x17/0x18, DES: 0x1/0x3) bij succesvol afgegeven tickets, en
        ontbrekende SPN's via 4769 met Status 0x7 (KDC_ERR_S_PRINCIPAL_UNKNOWN — de gevraagde
        servicenaam bestaat niet, typische NTLM-fallback-oorzaak). Leest System-event 11 (KDC)
        voor dubbele SPN's die daadwerkelijk aangevraagd zijn (aanvulling op de statische
        setspn -X-check in Get-HKBaseline), en System-events 39/40/41 (Kdcsvc) voor zwakke
        certificaatkoppelingen (KB5014754-gerelateerd). Aggregeert per maatregel, account,
        client en doel.

        Vereist Kerberos-auditing (succes) voor RC4/DES, en foutauditing voor Service Ticket
        Operations voor ontbrekende SPN's — zie Get-HKAuditPolicy / Test-HKAuditConfig.

    .PARAMETER ComputerName
        Host om te meten. Alleen de lokale machine wordt ondersteund.

    .PARAMETER SecurityStartRecordId
        Laatst gelezen EventRecordID in het Security-log (4768/4769).

    .PARAMETER SystemStartRecordId
        Laatst gelezen EventRecordID in het System-log (11/39/40/41).

    .OUTPUTS
        PSCustomObject met:
          - ComputerName, CheckedAtUtc
          - Collectors: leesstatus per log (SecurityLog, SystemLog)
          - Findings: geaggregeerde bevindingen (kerberos_rc4_des, missing_spn, duplicate_spn,
            cert_mapping)
          - LastSecurityRecordId, LastSystemRecordId: hoogste geziene RecordId per log

    .NOTES
        Fase 0. Alleen-lezen. De EventData-veldnamen van System-events 11/39/40/41 zijn, net als
        de LDAP-events in Get-HKLdapBinding, minder zeker dan 4768/4769 — zie de pilot-testlijst
        in docs/LESSONS.md.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [Nullable[long]]$SecurityStartRecordId,
        [Nullable[long]]$SystemStartRecordId
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKKerberos ondersteunt alleen de lokale machine."
    }

    $collectorStatus = [ordered]@{
        SecurityLog = 'ok'
        SystemLog   = 'ok'
    }

    try {
        $securityEvents = @(Get-HKWinEvent -LogName 'Security' -Id @(4768, 4769) -StartRecordId $SecurityStartRecordId -ComputerName $ComputerName)
    }
    catch {
        Write-Warning "Get-HKKerberos: Security-log (4768/4769) kon niet gelezen worden: $_"
        $securityEvents = @()
        $collectorStatus.SecurityLog = 'onbekend'
    }

    try {
        $systemEvents = @(Get-HKWinEvent -LogName 'System' -Id @(11, 39, 40, 41) -StartRecordId $SystemStartRecordId -ComputerName $ComputerName)
    }
    catch {
        Write-Warning "Get-HKKerberos: System-log (11/39/40/41) kon niet gelezen worden: $_"
        $systemEvents = @()
        $collectorStatus.SystemLog = 'onbekend'
    }

    $weakEncryptionTypes = @('0x17', '0x18', '0x1', '0x3')

    # kerberos_rc4_des: 4768/4769, alleen succesvol afgegeven tickets met zwak encryptietype.
    # Een mislukt ticket (bv. 0x7, zie missing_spn) heeft geen betekenisvol encryptietype.
    $rc4DesRows = @(
        foreach ($e in $securityEvents) {
            $encType = $e.EventData['TicketEncryptionType']
            if ($encType -notin $weakEncryptionTypes) { continue }

            $succeeded =
                if ($e.EventId -eq 4768) { $e.EventData['ResultCode'] -eq '0x0' }
                else { $e.EventData['Status'] -eq '0x0' }
            if (-not $succeeded) { continue }

            [pscustomobject]@{
                Measure        = 'kerberos_rc4_des'
                AccountName    = $e.EventData['TargetUserName']
                AccountSid     = $e.EventData['TargetSid']
                ClientFqdn     = $null
                ClientIp       = $e.EventData['IpAddress']
                Target         = $(if ($e.EventId -eq 4769) { $e.EventData['ServiceName'] } else { $null })
                TimeCreatedUtc = $e.TimeCreatedUtc
            }
        }
    )

    # missing_spn: 4769 met Status 0x7 (KDC_ERR_S_PRINCIPAL_UNKNOWN).
    $missingSpnRows = @(
        foreach ($e in $securityEvents) {
            if ($e.EventId -ne 4769) { continue }
            if ($e.EventData['Status'] -ne '0x7') { continue }

            [pscustomobject]@{
                Measure        = 'missing_spn'
                AccountName    = $e.EventData['TargetUserName']
                AccountSid     = $e.EventData['TargetSid']
                ClientFqdn     = $null
                ClientIp       = $e.EventData['IpAddress']
                Target         = $e.EventData['ServiceName']
                TimeCreatedUtc = $e.TimeCreatedUtc
            }
        }
    )

    # duplicate_spn: System-event 11 (KDC) — een daadwerkelijk aangevraagde SPN die aan meerdere
    # accounts hangt. Geen account/client, alleen de SPN zelf als Target.
    $duplicateSpnRows = @(
        foreach ($e in $systemEvents) {
            if ($e.EventId -ne 11) { continue }

            [pscustomobject]@{
                Measure        = 'duplicate_spn'
                AccountName    = $null
                AccountSid     = $null
                ClientFqdn     = $null
                ClientIp       = $null
                Target         = $e.EventData['ServicePrincipalName']
                TimeCreatedUtc = $e.TimeCreatedUtc
            }
        }
    )

    # cert_mapping: System-events 39/40/41 (Kdcsvc) — zwakke certificaatkoppeling.
    $certMappingRows = @(
        foreach ($e in $systemEvents) {
            if ($e.EventId -notin @(39, 40, 41)) { continue }

            [pscustomobject]@{
                Measure        = 'cert_mapping'
                AccountName    = $e.EventData['TargetUserName']
                AccountSid     = $e.EventData['TargetSid']
                ClientFqdn     = $null
                ClientIp       = $null
                Target         = $e.EventData['CertificateSubject']
                TimeCreatedUtc = $e.TimeCreatedUtc
            }
        }
    )

    $groupBy = @('Measure', 'AccountName', 'AccountSid', 'ClientFqdn', 'ClientIp', 'Target')
    $rows = @($rc4DesRows) + @($missingSpnRows) + @($duplicateSpnRows) + @($certMappingRows)

    $findings = [System.Collections.Generic.List[psobject]]::new()
    foreach ($row in @($rows | ConvertTo-HKAggregate -GroupBy $groupBy)) { $findings.Add($row) }

    $lastSecurityRecordId =
        if ($securityEvents.Count -gt 0) { ($securityEvents | Measure-Object -Property EventRecordId -Maximum).Maximum }
        else { $SecurityStartRecordId }
    $lastSystemRecordId =
        if ($systemEvents.Count -gt 0) { ($systemEvents | Measure-Object -Property EventRecordId -Maximum).Maximum }
        else { $SystemStartRecordId }

    [pscustomobject]@{
        ComputerName         = $ComputerName
        CheckedAtUtc         = (Get-Date).ToUniversalTime()
        Collectors           = [pscustomobject]$collectorStatus
        Findings             = $findings.ToArray()
        LastSecurityRecordId = $lastSecurityRecordId
        LastSystemRecordId   = $lastSystemRecordId
    }
}
