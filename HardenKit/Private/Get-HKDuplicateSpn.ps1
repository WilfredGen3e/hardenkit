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

    # setspn -X geeft ook bij een geslaagde run exitcode 1 (gezien op Server 2022 met
    # "found 0 group of duplicate SPNs."). De slotregel is daarom het succescriterium, niet de
    # exitcode.
    $output = @(& setspn.exe -X 2>&1 | ForEach-Object { "$_" })
    if (-not ($output -match '^\s*found \d+ group')) {
        throw "setspn.exe gaf exitcode $LASTEXITCODE`: $output"
    }

    @($output | ConvertFrom-HKSetspnOutput)
}
