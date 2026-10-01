function Export-HKData {
    <#
    .SYNOPSIS
        Roept alle relevante collectors aan en schrijft het resultaat als JSON weg.

    .DESCRIPTION
        Bepaalt de hostrol (Get-HKHostRole), roept op een DC alle fase 0-collectors aan
        (Get-HKBaseline, Get-HKNtlmUsage, Get-HKLdapBinding, Get-HKKerberos,
        Get-HKDomainHealth, Get-HKOutbound), aggregeert de resultaten en schrijft één
        JSON-bestand per host per dag volgens het vastgelegde schema (schemaversie, klantcode,
        hostnaam, rol, moduleversie, meetvenster, status per collector, findings). Houdt per
        log een statusbestand bij met de laatst gelezen RecordId voor incrementeel lezen.
        Gedeeltelijke uitval van een collector resulteert in status "onbekend" voor die
        collector, niet in een afgebroken run.

    .PARAMETER ClientCode
        Klantcode die in het JSON-bestand wordt opgenomen.

    .PARAMETER OutputPath
        Map waarin het JSON-bestand en het statusbestand worden weggeschreven.

    .OUTPUTS
        Geen; schrijft het JSON-bestand naar schijf.

    .NOTES
        Fase 0. Alleen-lezen (behalve het eigen status-/outputbestand van de module zelf).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ClientCode,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    throw "Export-HKData is nog niet geïmplementeerd."
}
