function Get-HKOperatingSystemInfo {
    <#
    .SYNOPSIS
        Leest OS-versie-informatie van een host.

    .DESCRIPTION
        Leest Caption, Version en BuildNumber via Win32_OperatingSystem.

    .PARAMETER ComputerName
        Host om te bevragen. Alleen de lokale machine wordt ondersteund — een bewuste
        vereenvoudiging, niet een technische beperking van Get-CimInstance zelf, voor een
        consistente remoting-houding over alle HardenKit-collectors heen (zie Get-HKAuditPolicy).

    .OUTPUTS
        PSCustomObject met Caption, Version, BuildNumber.

    .NOTES
        Fase 0. Alleen-lezen.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKOperatingSystemInfo ondersteunt alleen de lokale machine."
    }

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop

    [pscustomobject]@{
        Caption     = $os.Caption
        Version     = $os.Version
        BuildNumber = $os.BuildNumber
    }
}
