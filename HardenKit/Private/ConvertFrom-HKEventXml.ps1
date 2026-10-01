function ConvertFrom-HKEventXml {
    <#
    .SYNOPSIS
        Parsed de XML-representatie van één Windows-event naar een plat object.

    .DESCRIPTION
        Pure parsing-stap, los van het ophalen van het event zelf (zie Get-HKWinEvent), zodat de
        parsing-logica onafhankelijk van Windows getest kan worden met vaste XML-fixtures.
        Generiek bruikbaar voor elke eventlog-collector (zie docs/LESSONS.md): alleen deze
        functie hoeft de EventData-structuur te kennen, de I/O-laag niet.

    .PARAMETER Xml
        De XML-string zoals geretourneerd door een event-record z'n ToXml()-methode
        (bv. (Get-WinEvent ...)[0].ToXml()).

    .OUTPUTS
        PSCustomObject met TimeCreatedUtc ([datetime]), EventRecordId ([long]), EventId ([int]),
        Computer ([string]) en EventData ([hashtable], veldnaam -> waarde zoals in de
        EventData-sectie van het event).

    .NOTES
        Fase 0. Gaat ervan uit dat elk <Data>-element een Name-attribuut heeft, zoals bij alle
        eventlogs die HardenKit gebruikt; naamloze Data-elementen worden overgeslagen. De
        standaard XML-namespace op <Event> hoeft niet apart afgehandeld te worden: PowerShell's
        ingebouwde XML-adapter ontsluit elementen via dot-notation ongeacht namespace.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Xml
    )

    $doc = [xml]$Xml
    $system = $doc.Event.System

    $eventData = @{}
    foreach ($data in $doc.Event.EventData.Data) {
        if ($data.Name) {
            $eventData[$data.Name] = $data.'#text'
        }
    }

    [pscustomobject]@{
        TimeCreatedUtc = ([datetime]$system.TimeCreated.SystemTime).ToUniversalTime()
        EventRecordId  = [long]$system.EventRecordID
        EventId        = [int]$system.EventID
        Computer       = $system.Computer
        EventData      = $eventData
    }
}
