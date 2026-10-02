function Get-HKLdapAuditSettings {
    <#
    .SYNOPSIS
        Leest de LDAP-signing-vereiste, het LDAP-diagnostiekniveau en de channel binding-modus.

    .DESCRIPTION
        Leest LDAPServerIntegrity onder HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
        (1 = none, 2 = require signing), "16 LDAP Interface Events" onder
        HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics (verhoogd niveau nodig voor
        event 2889) en LdapEnforceChannelBinding onder dezelfde Parameters-sleutel (0 = never,
        1 = when supported/audit, 2 = always; nodig voor events 3039-3041). Alleen relevant op
        domain controllers.

    .PARAMETER ComputerName
        Host om te bevragen. Alleen de lokale machine wordt ondersteund: registry-remoting is
        hier bewust uitgesloten.

    .OUTPUTS
        PSCustomObject met LdapServerIntegrity ([int]), DiagnosticsLevel ([int]) en
        ChannelBindingMode ([int]).

    .NOTES
        Fase 0. Alleen-lezen. Ontbrekende waarden worden als 0 behandeld (LdapServerIntegrity:
        geen vaste default aangenomen, zie open vragen in CLAUDE.md voor de verificatie-status
        van deze registrynamen).
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKLdapAuditSettings ondersteunt alleen de lokale machine (registry-remoting is hier bewust uitgesloten)."
    }

    $ntdsParametersPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'

    $ldapServerIntegrity = (Get-ItemProperty -Path $ntdsParametersPath -Name 'LDAPServerIntegrity' -ErrorAction SilentlyContinue).LDAPServerIntegrity
    $diagLevel = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '16 LDAP Interface Events' -ErrorAction SilentlyContinue).'16 LDAP Interface Events'
    $channelBinding = (Get-ItemProperty -Path $ntdsParametersPath -Name 'LdapEnforceChannelBinding' -ErrorAction SilentlyContinue).LdapEnforceChannelBinding

    [pscustomobject]@{
        LdapServerIntegrity = if ($null -ne $ldapServerIntegrity) { [int]$ldapServerIntegrity } else { 0 }
        DiagnosticsLevel    = if ($null -ne $diagLevel) { [int]$diagLevel } else { 0 }
        ChannelBindingMode  = if ($null -ne $channelBinding) { [int]$channelBinding } else { 0 }
    }
}
