function Get-HKHostRole {
    <#
    .SYNOPSIS
        Bepaalt of een host een domain controller of member server is.

    .DESCRIPTION
        HardenKit kiest op basis van de hostrol welke collectors relevant zijn.
        Fase 0 richt zich uitsluitend op domain controllers; member servers volgen in fase 1.
        Leest alleen Win32_ComputerSystem.DomainRole uit, wijzigt niets.

    .PARAMETER ComputerName
        Host om te controleren. Standaard de lokale machine.

    .OUTPUTS
        String: 'DC', 'MemberServer' of 'Other'.

    .NOTES
        Fase 0. Alleen-lezen.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction Stop

    # DomainRole: 0/1 = standalone/member workstation, 2 = standalone server,
    # 3 = member server, 4 = backup DC, 5 = primary DC.
    switch ($cs.DomainRole) {
        5       { 'DC' }
        4       { 'DC' }
        3       { 'MemberServer' }
        default { 'Other' }
    }
}
