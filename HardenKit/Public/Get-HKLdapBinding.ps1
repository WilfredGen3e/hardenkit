function Get-HKLdapBinding {
    <#
    .SYNOPSIS
        Meet unsigned LDAP-binds en ontbrekende channel binding.

    .DESCRIPTION
        Leest Directory Service-events 2887/2889 (unsigned of simple bind; 2889 vereist
        verhoogde LDAP-diagnostiek) en 3039-3041 (channel binding in auditstand). Aggregeert
        per client-IP en account. Ontbrekende diagnostiek-instelling levert "onbekend" op.

    .PARAMETER ComputerName
        Host om te meten. Standaard de lokale machine.

    .PARAMETER Since
        Vanaf welk tijdstip (UTC) gemeten wordt. Standaard de laatst gelezen RecordId.

    .OUTPUTS
        PSCustomObject[] met geaggregeerde LDAP-bindbevindingen.

    .NOTES
        Fase 0. Alleen-lezen.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [datetime]$Since
    )

    throw "Get-HKLdapBinding is nog niet geïmplementeerd."
}
