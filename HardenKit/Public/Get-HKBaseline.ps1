function Get-HKBaseline {
    <#
    .SYNOPSIS
        Nulmeting van de DC-configuratie.

    .DESCRIPTION
        Legt vast hoe het domein er vóór de meting voor staat: OS-versie, rol, lijst van alle
        DC's, auditinstellingen, Security-log grootte/leeftijd, LDAP-diagnostiekniveau, LDAP
        signing/channel binding, LmCompatibilityLevel, NTLM-beperkingen, SMB1-status,
        Print Spooler-status, dubbele SPN's (setspn -X), tijdbron van de PDC-emulator,
        SYSVOL-replicatie en krbtgt-wachtwoordleeftijd. Alleen-lezen.

    .PARAMETER ComputerName
        Host om te meten. Standaard de lokale machine.

    .OUTPUTS
        PSCustomObject met de nulmeting-resultaten.

    .NOTES
        Fase 0. Alleen-lezen.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    throw "Get-HKBaseline is nog niet geïmplementeerd."
}
