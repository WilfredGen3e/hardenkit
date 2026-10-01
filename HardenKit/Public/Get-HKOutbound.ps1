function Get-HKOutbound {
    <#
    .SYNOPSIS
        Momentopname van uitgaande verbindingen vanaf de DC, met proces en DNS-naam.

    .DESCRIPTION
        Legt uitgaande verbindingen vast (proces + bestemming, via DNS-cache en optioneel
        tijdelijk Security-event 5156 of Sysmon event 3) als basis voor een allowlist-voorstel
        voor uitgaand verkeer van DC's. Bedoeld om te onderbouwen dat internettoegang van DC's
        dicht kan zonder noodzakelijk verkeer te breken.

    .PARAMETER ComputerName
        Host om te meten. Standaard de lokale machine.

    .OUTPUTS
        PSCustomObject[] met proces, bestemming (IP/DNS) en poort per uitgaande verbinding.

    .NOTES
        Fase 0. Alleen-lezen. Event 5156 wordt alleen tijdelijk ingezet, niet structureel.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    throw "Get-HKOutbound is nog niet geïmplementeerd."
}
