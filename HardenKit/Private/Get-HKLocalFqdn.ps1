function Get-HKLocalFqdn {
    <#
    .SYNOPSIS
        Bepaalt de FQDN van de lokale machine.

    .DESCRIPTION
        Kleine gedeelde helper (DNS-lookup op de computernaam), zodat elke plek die de lokale
        FQDN nodig heeft (Get-HKDomainControllerInfo, Export-HKData) dezelfde logica gebruikt.

    .OUTPUTS
        String.

    .NOTES
        Fase 0. Alleen-lezen.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    ([System.Net.Dns]::GetHostByName($env:COMPUTERNAME)).HostName
}
