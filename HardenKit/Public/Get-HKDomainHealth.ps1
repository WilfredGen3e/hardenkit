function Get-HKDomainHealth {
    <#
    .SYNOPSIS
        Meet Netlogon-weigeringen, lockouts, onbekende subnetten, tijdsafwijking en replicatiefouten.

    .DESCRIPTION
        Leest System-events 5827/5828 (Netlogon secure channel-weigeringen), 5816-5819
        (Netlogon-verzadiging), 5807/NO_CLIENT_SITE (onbekende subnetten), W32Time-events
        (tijdsynchronisatie), Directory Service/DFSR-events (o.a. 1311, 1865, 2042) voor
        replicatiefouten, en Security-events 4740/4625 (lockouts/mislukte logons). Dit zijn
        grotendeels "al stuk"-bevindingen: problemen die nu al weigeringen veroorzaken.

    .PARAMETER ComputerName
        Host om te meten. Standaard de lokale machine.

    .PARAMETER Since
        Vanaf welk tijdstip (UTC) gemeten wordt. Standaard de laatst gelezen RecordId.

    .OUTPUTS
        PSCustomObject[] met geaggregeerde domeinhealth-bevindingen.

    .NOTES
        Fase 0. Alleen-lezen.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [datetime]$Since
    )

    throw "Get-HKDomainHealth is nog niet geïmplementeerd."
}
