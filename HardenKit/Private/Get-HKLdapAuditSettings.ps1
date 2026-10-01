function Get-HKLdapAuditSettings {
    <#
    .SYNOPSIS
        Leest het LDAP-diagnostiekniveau en de channel binding-modus.

    .DESCRIPTION
        Leest "16 LDAP Interface Events" onder
        HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics (verhoogd niveau nodig voor
        event 2889) en LdapEnforceChannelBinding onder
        HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters (0 = never, 1 = when
        supported/audit, 2 = always; nodig voor events 3039-3041). Alleen relevant op domain
        controllers.

    .PARAMETER ComputerName
        Host om te bevragen. Alleen de lokale machine wordt ondersteund: registry-remoting is
        hier bewust uitgesloten.

    .OUTPUTS
        PSCustomObject met DiagnosticsLevel ([int]) en ChannelBindingMode ([int]).

    .NOTES
        Fase 0. Alleen-lezen. Ontbrekende waarden worden als 0 (uit/never) behandeld.
        Registrynaam/-pad nog te verifiëren op een echte DC (zie open vragen in CLAUDE.md).
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKLdapAuditSettings ondersteunt alleen de lokale machine (registry-remoting is hier bewust uitgesloten)."
    }

    $diagLevel = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '16 LDAP Interface Events' -ErrorAction SilentlyContinue).'16 LDAP Interface Events'
    $channelBinding = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding' -ErrorAction SilentlyContinue).LdapEnforceChannelBinding

    [pscustomobject]@{
        DiagnosticsLevel   = if ($null -ne $diagLevel) { [int]$diagLevel } else { 0 }
        ChannelBindingMode = if ($null -ne $channelBinding) { [int]$channelBinding } else { 0 }
    }
}
