function New-HKReport {
    <#
    .SYNOPSIS
        Genereert één zelfstandig HTML-rapport uit een map met JSON-exports.

    .DESCRIPTION
        Leest alle JSON-bestanden van een klant (van alle DC's, over de volledige meetperiode),
        past de correlatieregels toe (o.a. NTLM-fallback door ontbrekende SPN, NTLM naar IP/alias,
        gedeelde oorzaken, drempelwaarden) en bepaalt per maatregel één status: groen, oranje,
        rood, onbekend of al stuk. Schrijft één zelfstandig HTML-bestand (data als JSON inline,
        geen externe scripts/fonts, werkt offline) met een stoplicht-overzicht, per maatregel de
        betrokken objecten en voorgestelde actie, een aparte sectie "al stuk", en een
        allowlist-voorstel voor uitgaand verkeer.

    .PARAMETER InputPath
        Map met JSON-exports van één klant.

    .PARAMETER OutputPath
        Pad van het te genereren HTML-rapport.

    .PARAMETER MinimumDays
        Minimaal aantal gemeten dagen voor een groene status. Standaard 28.

    .OUTPUTS
        Geen; schrijft het HTML-rapport naar schijf.

    .NOTES
        Fase 0. Alleen-lezen.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InputPath,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [int]$MinimumDays = 28
    )

    throw "New-HKReport is nog niet geïmplementeerd."
}
