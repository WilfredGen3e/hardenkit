function Test-HKIsIpOrAlias {
    <#
    .SYNOPSIS
        Bepaalt of een NTLM-doelnaam een IP-adres of een alias is in plaats van een FQDN.

    .DESCRIPTION
        Basis voor de PRD-correlatieregel "NTLM naar IP of alias": een doel is verdacht als het
        een IP-adres is (IPv4 of IPv6), of een naam zonder punt (dus geen FQDN — typisch een
        NetBIOS-naam of DNS-alias/CNAME-achtige kortere naam).

    .PARAMETER Target
        De doelnaam/het doel-adres zoals in de eventdata staat.

    .OUTPUTS
        Boolean.

    .NOTES
        Fase 0. Pure functie, geen I/O.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Target
    )

    if ([string]::IsNullOrWhiteSpace($Target)) {
        return $false
    }

    $trimmed = $Target.Trim()

    [ipaddress]$parsedIp = $null
    if ([ipaddress]::TryParse($trimmed, [ref]$parsedIp)) {
        return $true
    }

    # Geen punt in de naam: geen FQDN, dus een NetBIOS-naam of alias.
    -not $trimmed.Contains('.')
}
