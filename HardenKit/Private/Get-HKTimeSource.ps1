function Get-HKTimeSource {
    <#
    .SYNOPSIS
        Leest de geconfigureerde tijdbron via w32tm.

    .DESCRIPTION
        Roept 'w32tm /query /source' aan. Relevant is vooral de uitkomst op de PDC-emulator
        (zie Get-HKDomainControllerInfo); op andere DC's hoort de bron doorgaans de
        domeinhiërarchie te zijn (NT5DS).

    .PARAMETER ComputerName
        Host om te bevragen. Alleen de lokale machine wordt ondersteund.

    .OUTPUTS
        PSCustomObject met Source ([string]).

    .NOTES
        Fase 0. Alleen-lezen.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKTimeSource ondersteunt alleen de lokale machine."
    }

    $output = & w32tm.exe /query /source 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "w32tm.exe gaf exitcode $LASTEXITCODE`: $output"
    }

    [pscustomobject]@{
        Source = ($output | Select-Object -Last 1).ToString().Trim()
    }
}
