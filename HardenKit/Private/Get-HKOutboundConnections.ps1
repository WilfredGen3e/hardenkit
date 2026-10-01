function Get-HKOutboundConnections {
    <#
    .SYNOPSIS
        Momentopname van actieve uitgaande TCP-verbindingen, met proces en DNS-naam.

    .DESCRIPTION
        Leest actieve ("Established") TCP-verbindingen via Get-NetTCPConnection, zoekt de
        procesnaam op via Get-Process en de DNS-naam via de lokale DNS-clientcache
        (Get-DnsClientCache — geen actieve lookup, alleen wat al gecachet is; een DC hoeft
        hiervoor niet naar internet). Loopback-verbindingen worden overgeslagen.

    .PARAMETER ComputerName
        Host om te bevragen. Alleen de lokale machine wordt ondersteund.

    .OUTPUTS
        PSCustomObject[] in het interne rij-formaat (Measure/AccountName/AccountSid/ClientFqdn/
        ClientIp/Target/TimeCreatedUtc), klaar voor ConvertTo-HKAggregate. Measure is altijd
        'outbound'; Target is de procesnaam (niet een account/client zoals bij de
        eventlog-collectors — dit is een bewuste hergebruik van hetzelfde schema voor het
        allowlist-voorstel per proces uit de PRD).

    .NOTES
        Fase 0. Alleen-lezen. Vereist Get-NetTCPConnection (NetTCPIP-module, standaard aanwezig
        op Windows Server 2016+).
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKOutboundConnections ondersteunt alleen de lokale machine."
    }

    $snapshotTimeUtc = (Get-Date).ToUniversalTime()

    $connections = Get-NetTCPConnection -State Established -ErrorAction Stop |
        Where-Object { $_.RemoteAddress -notin @('127.0.0.1', '::1') }

    $dnsCache = @{}
    try {
        foreach ($entry in Get-DnsClientCache -ErrorAction Stop) {
            if ($entry.Data -and -not $dnsCache.ContainsKey($entry.Data)) {
                $dnsCache[$entry.Data] = $entry.Name
            }
        }
    }
    catch {
        # DNS-cache is informatief (vult ClientFqdn aan); geen harde afhankelijkheid, dus hier
        # bewust geen throw — zonder cache blijft ClientFqdn leeg, ClientIp blijft bruikbaar.
        Write-Verbose "Get-HKOutboundConnections: DNS-clientcache kon niet gelezen worden: $_"
    }

    $processCache = @{}

    $rows = foreach ($conn in $connections) {
        $procId = $conn.OwningProcess
        if (-not $processCache.ContainsKey($procId)) {
            $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
            $processCache[$procId] = if ($proc) { $proc.ProcessName } else { "pid:$procId" }
        }

        [pscustomobject]@{
            Measure        = 'outbound'
            AccountName    = $null
            AccountSid     = $null
            ClientFqdn     = $dnsCache[$conn.RemoteAddress]
            ClientIp       = $conn.RemoteAddress
            Target         = $processCache[$procId]
            TimeCreatedUtc = $snapshotTimeUtc
        }
    }

    @($rows)
}
