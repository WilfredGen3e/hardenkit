function Get-HKDuplicateSpn {
    <#
    .SYNOPSIS
        Zoekt dubbele SPN's in het domein.

    .DESCRIPTION
        Roept 'setspn.exe -X' aan en parsed de uitvoer via ConvertFrom-HKSetspnOutput.

    .PARAMETER ComputerName
        Host om te bevragen. Alleen de lokale machine wordt ondersteund.

    .OUTPUTS
        PSCustomObject[] met Spn en Accounts. Leeg als er geen dubbele SPN's zijn.

    .NOTES
        Fase 0. Alleen-lezen. Vereist setspn.exe (Windows, RSAT/AD DS-rol).
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKDuplicateSpn ondersteunt alleen de lokale machine."
    }

    $output = & setspn.exe -X 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "setspn.exe gaf exitcode $LASTEXITCODE`: $output"
    }

    @($output | ConvertFrom-HKSetspnOutput)
}
