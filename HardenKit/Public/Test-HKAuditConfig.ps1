function Test-HKAuditConfig {
    <#
    .SYNOPSIS
        Controleert of de audit- en loginstellingen aanstaan die HardenKit nodig heeft.

    .DESCRIPTION
        Leest auditpol-categorieën en eventlog-instellingen (grootte, retentie) uit en bepaalt
        per maatregel of de benodigde logbron aanwezig is. Dit is de basis voor de regel
        "onbekend is niet groen": ontbrekende auditinstellingen leiden tot status "onbekend",
        nooit tot "veilig". Wijzigt zelf niets; het aanzetten van auditinstellingen gaat via
        een aparte, gemelde GPO-wijziging.

    .PARAMETER ComputerName
        Host om te controleren. Standaard de lokale machine.

    .OUTPUTS
        PSCustomObject met per maatregel of de vereiste auditinstelling aanstaat.

    .NOTES
        Fase 0. Alleen-lezen.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    throw "Test-HKAuditConfig is nog niet geïmplementeerd."
}
