function Get-HKWinEvent {
    <#
    .SYNOPSIS
        Leest events uit een eventlog met een XPath-filter, optioneel incrementeel vanaf een
        laatst gelezen RecordId.

    .DESCRIPTION
        Dunne I/O-laag rond Get-WinEvent: bouwt een XPath-filter uit LogName/Id/StartRecordId
        en parsed elk teruggegeven event via ConvertFrom-HKEventXml naar een plat object. Dit is
        het gedeelde incrementele leespatroon uit de PRD-NFR "Belasting DC": XPath-filters,
        incrementeel lezen vanaf de laatste RecordId per log. "Geen events gevonden" is geen
        fout en geeft een lege lijst terug, niet een afgebroken run.

    .PARAMETER LogName
        Naam van het eventlog, bv. 'Security' of 'Microsoft-Windows-NTLM/Operational'.

    .PARAMETER Id
        Event-ID('s) om te lezen.

    .PARAMETER StartRecordId
        Als opgegeven: alleen events met EventRecordID groter dan deze waarde.

    .PARAMETER ComputerName
        Host om te bevragen. Alleen de lokale machine wordt ondersteund.

    .OUTPUTS
        PSCustomObject[] zoals geretourneerd door ConvertFrom-HKEventXml. Leeg als er geen
        (nieuwe) events zijn.

    .NOTES
        Fase 0. Alleen-lezen. Gebruik altijd @(...) rond de aanroep (zie docs/LESSONS.md): een
        lege lijst komt bij direct aanroepen terug als $null, niet als een lege array.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogName,

        [Parameter(Mandatory)]
        [int[]]$Id,

        [Nullable[long]]$StartRecordId,

        [string]$ComputerName = $env:COMPUTERNAME
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKWinEvent ondersteunt alleen de lokale machine."
    }

    $idClause = ($Id | ForEach-Object { "EventID=$_" }) -join ' or '
    if ($Id.Count -gt 1) { $idClause = "($idClause)" }

    $xpath =
        if ($null -ne $StartRecordId) { "*[System[$idClause and EventRecordID > $StartRecordId]]" }
        else { "*[System[$idClause]]" }

    try {
        $events = Get-WinEvent -LogName $LogName -FilterXPath $xpath -ErrorAction Stop
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            return @()
        }
        throw
    }

    $events | ForEach-Object { ConvertFrom-HKEventXml -Xml $_.ToXml() }
}
