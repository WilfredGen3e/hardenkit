function ConvertTo-HKHtmlEncoded {
    <#
    .SYNOPSIS
        HTML-encodeert een waarde, veilig voor $null.

    .DESCRIPTION
        Elke string die uit AD/eventdata komt (accountnamen, hostnamen, SPN's, IP's) en in de
        HTML van New-HKReport terechtkomt, moet hierdoorheen — een rapport is geen vertrouwde
        omgeving voor rauwe string-interpolatie: een accountnaam met bv. "<script>" erin mag de
        pagina niet kunnen breken.

    .PARAMETER Value
        De waarde om te encoderen. $null of leeg geeft een lege string terug.

    .OUTPUTS
        String.

    .NOTES
        Fase 0. Pure functie, geen I/O.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return '' }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}
