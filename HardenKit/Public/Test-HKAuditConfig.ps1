function Test-HKAuditConfig {
    <#
    .SYNOPSIS
        Controleert of de audit- en loginstellingen aanstaan die HardenKit nodig heeft.

    .DESCRIPTION
        Leest auditpol-subcategorieën, NTLM- en LDAP-auditregistrywaarden en Security-log
        metadata uit, en bepaalt per fase 0-maatregel of aan de voorwaarde voor een betrouwbare
        meting is voldaan. Dit is de basis voor de regel "onbekend is niet groen": een maatregel
        waarvan de benodigde auditinstelling ontbreekt, uitstaat of niet uit te lezen is, krijgt
        nooit zomaar de status 'Ok'. Wijzigt zelf niets; het aanzetten van auditinstellingen
        gaat via een aparte, gemelde GPO-wijziging.

        Gedeeltelijke uitval (een bron niet leesbaar, rechten ontbreken) resulteert in status
        'Onbekend' voor de maatregelen die van die bron afhangen, niet in een afgebroken run.

    .PARAMETER ComputerName
        Host om te controleren. Alleen de lokale machine wordt ondersteund: auditpol.exe en de
        relevante registrysleutels worden bewust niet remote uitgelezen.

    .OUTPUTS
        PSCustomObject met:
          - ComputerName, CheckedAtUtc
          - Collectors: leesstatus per onderliggende bron (AuditPolicy, SecurityLog, NtlmAudit, LdapAudit)
          - SecurityLog: grootte/record-/leeftijdinformatie van het Security-log ($null bij fout)
          - Measures: per fase 0-maatregel de voorwaarde, status (Ok/NietVoldaan/Onbekend) en reden

    .NOTES
        Fase 0. Alleen-lezen. Zie Get-HKAuditPolicy, Get-HKNtlmAuditSetting en
        Get-HKLdapAuditSettings voor bekende beperkingen (locale-afhankelijke auditpol-tekst,
        nog te verifiëren registrynamen).
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Test-HKAuditConfig ondersteunt alleen de lokale machine."
    }

    $collectorStatus = [ordered]@{
        AuditPolicy = 'ok'
        SecurityLog = 'ok'
        NtlmAudit   = 'ok'
        LdapAudit   = 'ok'
    }

    try {
        $auditPolicy = Get-HKAuditPolicy -ComputerName $ComputerName
    }
    catch {
        Write-Warning "Test-HKAuditConfig: auditpol kon niet gelezen worden: $_"
        $auditPolicy = $null
        $collectorStatus.AuditPolicy = 'onbekend'
    }

    try {
        $securityLog = Get-HKSecurityLogInfo -ComputerName $ComputerName
    }
    catch {
        Write-Warning "Test-HKAuditConfig: Security-log kon niet gelezen worden: $_"
        $securityLog = $null
        $collectorStatus.SecurityLog = 'onbekend'
    }

    try {
        $ntlmAudit = Get-HKNtlmAuditSetting -ComputerName $ComputerName
    }
    catch {
        Write-Warning "Test-HKAuditConfig: NTLM-auditinstelling kon niet gelezen worden: $_"
        $ntlmAudit = $null
        $collectorStatus.NtlmAudit = 'onbekend'
    }

    try {
        $ldapAudit = Get-HKLdapAuditSettings -ComputerName $ComputerName
    }
    catch {
        Write-Warning "Test-HKAuditConfig: LDAP-auditinstellingen konden niet gelezen worden: $_"
        $ldapAudit = $null
        $collectorStatus.LdapAudit = 'onbekend'
    }

    # Elke fase 0-maatregel met de bijbehorende voorwaarde (zie PRD, kolom "Voorwaarde") en een
    # predicate die bepaalt of eraan voldaan is. Als de onderliggende bron niet gelezen kon
    # worden ('onbekend' in $collectorStatus), is de maatregel altijd 'Onbekend', ongeacht de
    # predicate.
    $definitions = @(
        @{ Measure = 'ntlmv1';                   Voorwaarde = 'Logon-auditing (succes)';                 Bron = 'AuditPolicy'; Predicate = { $auditPolicy['Logon'].Success } }
        @{ Measure = 'ntlm_8004';                Voorwaarde = 'NTLM-audit in domein aan';                Bron = 'NtlmAudit';   Predicate = { $ntlmAudit.Enabled } }
        @{ Measure = 'ntlm_4776';                Voorwaarde = 'Audit Credential Validation (succes)';    Bron = 'AuditPolicy'; Predicate = { $auditPolicy['Credential Validation'].Success } }
        @{ Measure = 'ldap_signing';             Voorwaarde = 'Verhoogde LDAP-diagnostiek (niveau >= 2)'; Bron = 'LdapAudit';  Predicate = { $ldapAudit.DiagnosticsLevel -ge 2 } }
        @{ Measure = 'ldap_channel_binding';     Voorwaarde = 'Channel binding in auditstand';           Bron = 'LdapAudit';   Predicate = { $ldapAudit.ChannelBindingMode -eq 1 } }
        @{ Measure = 'kerberos_rc4_des';         Voorwaarde = 'Kerberos-auditing (succes)';               Bron = 'AuditPolicy'; Predicate = { $auditPolicy['Kerberos Authentication Service'].Success -and $auditPolicy['Kerberos Service Ticket Operations'].Success } }
        @{ Measure = 'missing_spn';              Voorwaarde = 'Foutauditing Service Ticket Operations';  Bron = 'AuditPolicy'; Predicate = { $auditPolicy['Kerberos Service Ticket Operations'].Failure } }
        @{ Measure = 'lockouts';                 Voorwaarde = 'Logon-auditing (succes en fout)';         Bron = 'AuditPolicy'; Predicate = { $auditPolicy['Logon'].Success -and $auditPolicy['Logon'].Failure } }
        @{ Measure = 'duplicate_spn';            Voorwaarde = 'Geen';                                    Bron = $null;         Predicate = { $true } }
        @{ Measure = 'netlogon_secure_channel';  Voorwaarde = 'Geen';                                    Bron = $null;         Predicate = { $true } }
        @{ Measure = 'cert_mapping';              Voorwaarde = 'Geen';                                   Bron = $null;         Predicate = { $true } }
        @{ Measure = 'netlogon_saturation';      Voorwaarde = 'Geen';                                    Bron = $null;         Predicate = { $true } }
        @{ Measure = 'unknown_subnets';          Voorwaarde = 'Geen';                                    Bron = $null;         Predicate = { $true } }
        @{ Measure = 'time_sync';                Voorwaarde = 'Geen';                                    Bron = $null;         Predicate = { $true } }
        @{ Measure = 'replication';              Voorwaarde = 'Geen';                                    Bron = $null;         Predicate = { $true } }
        @{ Measure = 'outbound';                 Voorwaarde = 'Geen (5156 alleen tijdelijk)';            Bron = $null;         Predicate = { $true } }
    )

    $measures = foreach ($def in $definitions) {
        $bronOnbekend = $def.Bron -and $collectorStatus[$def.Bron] -eq 'onbekend'

        if ($bronOnbekend) {
            $status = 'Onbekend'
            $reden = "Bron '$($def.Bron)' kon niet uitgelezen worden."
        }
        else {
            if (& $def.Predicate) {
                $status = 'Ok'
                $reden = 'Voorwaarde voldaan.'
            }
            else {
                $status = 'NietVoldaan'
                $reden = 'Voorwaarde actief gecontroleerd, maar niet voldaan.'
            }
        }

        [pscustomobject]@{
            Measure    = $def.Measure
            Voorwaarde = $def.Voorwaarde
            Status     = $status
            Reden      = $reden
        }
    }

    [pscustomobject]@{
        ComputerName = $ComputerName
        CheckedAtUtc = (Get-Date).ToUniversalTime()
        Collectors   = [pscustomobject]$collectorStatus
        SecurityLog  = $securityLog
        Measures     = $measures
    }
}
