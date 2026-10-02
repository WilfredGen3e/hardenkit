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

    # Klassieke logs (Directory Service, Netlogon in System) hebben vaak <Data> zonder Name:
    # die op positie bewaren als '#0', '#1', ... (index binnen alle Data-elementen), in plaats
    # van weggooien.
    $eventData = @{}
    $index = 0
    foreach ($data in @($doc.Event.EventData.ChildNodes | Where-Object { $_.LocalName -eq 'Data' })) {
        $value = if ($data.IsEmpty -or $data.InnerText -eq '') { $null } else { $data.InnerText }
        $name = $data.GetAttribute('Name')
        if ($name) { $eventData[$name] = $value } else { $eventData["#$index"] = $value }
        $index++
    }

    # InnerText i.p.v. de property zelf: <EventID Qualifiers="16384">2889</EventID> (klassieke
    # providers) geeft anders een XmlElement terug in plaats van een string (gezien op lab-DC).
    [pscustomobject]@{
        TimeCreatedUtc = ([datetime]$system.TimeCreated.GetAttribute('SystemTime')).ToUniversalTime()
        EventRecordId  = [long]$system.SelectSingleNode("*[local-name()='EventRecordID']").InnerText
        EventId        = [int]$system.SelectSingleNode("*[local-name()='EventID']").InnerText
        Computer       = $system.SelectSingleNode("*[local-name()='Computer']").InnerText
        EventData      = $eventData
    }
}
