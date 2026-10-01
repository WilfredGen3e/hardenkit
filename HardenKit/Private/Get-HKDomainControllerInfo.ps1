function Get-HKDomainControllerInfo {
    <#
    .SYNOPSIS
        Haalt de lijst van domain controllers in het domein op en bepaalt of deze host de
        PDC-emulator is.

    .DESCRIPTION
        Gebruikt System.DirectoryServices.ActiveDirectory (.NET, vereist geen
        ActiveDirectory-module) om alle DC's in het huidige domein en de houder van de
        PDC-emulatorrol op te halen.

    .PARAMETER ComputerName
        Host om te bevragen. Alleen de lokale machine wordt ondersteund.

    .OUTPUTS
        PSCustomObject met DomainControllers ([string[]] FQDN's), PdcEmulator ([string] FQDN)
        en IsPdcEmulator ([bool], voor deze host).

    .NOTES
        Fase 0. Alleen-lezen. Vereist dat deze host domeinlid is; faalt op een workgroup-host.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKDomainControllerInfo ondersteunt alleen de lokale machine."
    }

    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainControllers = @($domain.DomainControllers | ForEach-Object { $_.Name })
    $pdcEmulator = $domain.PdcRoleOwner.Name
    $localFqdn = Get-HKLocalFqdn

    [pscustomobject]@{
        DomainControllers = $domainControllers
        PdcEmulator       = $pdcEmulator
        IsPdcEmulator     = [bool]($pdcEmulator -and $localFqdn -and ($pdcEmulator -eq $localFqdn))
    }
}
