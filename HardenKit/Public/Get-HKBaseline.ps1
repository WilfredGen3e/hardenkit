function Get-HKBaseline {
    <#
    .SYNOPSIS
        Nulmeting van de DC-configuratie.

    .DESCRIPTION
        Legt vast hoe het domein er vóór de meting voor staat: OS-versie, rol (PDC-emulator) en
        lijst van alle DC's, LDAP-signing/diagnostiekniveau/channel binding, LmCompatibilityLevel
        en NTLM-verzendrestricties, SMB1-status, Print Spooler-status, dubbele SPN's, tijdbron,
        SYSVOL-replicatietechnologie en -gereedheid, krbtgt-wachtwoordleeftijd, en Security-log
        grootte/oudste event. Gedeeltelijke uitval (een bron niet leesbaar, rechten ontbreken)
        resulteert in status 'onbekend' voor die bron, niet in een afgebroken run.

    .PARAMETER ComputerName
        Host om te meten. Alleen de lokale machine wordt ondersteund.

    .OUTPUTS
        PSCustomObject met:
          - ComputerName, CheckedAtUtc
          - Collectors: leesstatus per onderliggende bron
          - OperatingSystem, DomainControllers, DuplicateSpn, Krbtgt, TimeSource, Sysvol,
            SmbNtlmConfig, LdapAudit, SecurityLog: de nulmeting-resultaten per onderdeel
            ($null bij een falende bron)

    .NOTES
        Fase 0. Alleen-lezen.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKBaseline ondersteunt alleen de lokale machine."
    }

    $collectorStatus = [ordered]@{
        OperatingSystem   = 'ok'
        DomainControllers = 'ok'
        DuplicateSpn      = 'ok'
        Krbtgt            = 'ok'
        TimeSource        = 'ok'
        Sysvol            = 'ok'
        SmbNtlmConfig     = 'ok'
        LdapAudit         = 'ok'
        SecurityLog       = 'ok'
    }

    try {
        $operatingSystem = Get-HKOperatingSystemInfo -ComputerName $ComputerName
    }
    catch {
        Write-Warning "Get-HKBaseline: OS-informatie kon niet gelezen worden: $_"
        $operatingSystem = $null
        $collectorStatus.OperatingSystem = 'onbekend'
    }

    try {
        $domainControllers = Get-HKDomainControllerInfo -ComputerName $ComputerName
    }
    catch {
        Write-Warning "Get-HKBaseline: lijst van domain controllers kon niet gelezen worden: $_"
        $domainControllers = $null
        $collectorStatus.DomainControllers = 'onbekend'
    }

    try {
        # @(...) rond de aanroep: Get-HKDuplicateSpn geeft $null terug (niet een lege array) als
        # er geen dubbele SPN's zijn gevonden — standaard PowerShell-gedrag bij een functie die
        # een lege array als laatste statement heeft. @(...) maakt dit betrouwbaar @().
        $duplicateSpn = @(Get-HKDuplicateSpn -ComputerName $ComputerName)
    }
    catch {
        Write-Warning "Get-HKBaseline: dubbele SPN's konden niet gelezen worden: $_"
        $duplicateSpn = $null
        $collectorStatus.DuplicateSpn = 'onbekend'
    }

    try {
        $krbtgt = Get-HKKrbtgtAge -ComputerName $ComputerName
    }
    catch {
        Write-Warning "Get-HKBaseline: krbtgt-wachtwoordleeftijd kon niet gelezen worden: $_"
        $krbtgt = $null
        $collectorStatus.Krbtgt = 'onbekend'
    }

    try {
        $timeSource = Get-HKTimeSource -ComputerName $ComputerName
    }
    catch {
        Write-Warning "Get-HKBaseline: tijdbron kon niet gelezen worden: $_"
        $timeSource = $null
        $collectorStatus.TimeSource = 'onbekend'
    }

    try {
        $sysvol = Get-HKSysvolReplicationInfo -ComputerName $ComputerName
    }
    catch {
        Write-Warning "Get-HKBaseline: SYSVOL-replicatie-informatie kon niet gelezen worden: $_"
        $sysvol = $null
        $collectorStatus.Sysvol = 'onbekend'
    }

    try {
        $smbNtlmConfig = Get-HKSmbNtlmConfig -ComputerName $ComputerName
    }
    catch {
        Write-Warning "Get-HKBaseline: SMB/NTLM-configuratie kon niet gelezen worden: $_"
        $smbNtlmConfig = $null
        $collectorStatus.SmbNtlmConfig = 'onbekend'
    }

    try {
        $ldapAudit = Get-HKLdapAuditSettings -ComputerName $ComputerName
    }
    catch {
        Write-Warning "Get-HKBaseline: LDAP-auditinstellingen konden niet gelezen worden: $_"
        $ldapAudit = $null
        $collectorStatus.LdapAudit = 'onbekend'
    }

    try {
        $securityLog = Get-HKSecurityLogInfo -ComputerName $ComputerName
    }
    catch {
        Write-Warning "Get-HKBaseline: Security-log kon niet gelezen worden: $_"
        $securityLog = $null
        $collectorStatus.SecurityLog = 'onbekend'
    }

    [pscustomobject]@{
        ComputerName      = $ComputerName
        CheckedAtUtc      = (Get-Date).ToUniversalTime()
        Collectors        = [pscustomobject]$collectorStatus
        OperatingSystem   = $operatingSystem
        DomainControllers = $domainControllers
        DuplicateSpn      = $duplicateSpn
        Krbtgt            = $krbtgt
        TimeSource        = $timeSource
        Sysvol            = $sysvol
        SmbNtlmConfig     = $smbNtlmConfig
        LdapAudit         = $ldapAudit
        SecurityLog       = $securityLog
    }
}
