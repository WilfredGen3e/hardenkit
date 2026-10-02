function ConvertTo-HKNormalizedSpnTarget {
    <#
    .SYNOPSIS
        Normaliseert een SPN of servernaam tot het kale servicedeel, voor correlatie tussen
        missing_spn- en ntlm_8004-findings.

    .DESCRIPTION
        Haalt bij een SPN (bv. "HTTP/fileserver.contoso.com") de klasse voor de slash weg en
        een eventueel poortnummer na een dubbele punt, en zet het resultaat in lowercase.
        "fileserver.contoso.com" (zonder klasse-prefix) blijft ongewijzigd behalve lowercase.

    .PARAMETER Value
        De SPN of servernaam om te normaliseren.

    .OUTPUTS
        String, of $null bij lege invoer.

    .NOTES
        Fase 0. Pure functie, geen I/O. Vereenvoudigde matching — zie Resolve-HKReportModel
        voor de volledige correlatieregel en de bekende beperking t.o.v. de letterlijke
        PRD-regel (geen client-matching).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $service = if ($Value.Contains('/')) { $Value.Split('/', 2)[1] } else { $Value }
    $service.Split(':', 2)[0].Trim().ToLowerInvariant()
}
