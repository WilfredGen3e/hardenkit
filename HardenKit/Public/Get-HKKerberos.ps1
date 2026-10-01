function Get-HKKerberos {
    <#
    .SYNOPSIS
        Meet Kerberos RC4/DES-gebruik, ontbrekende SPN's, dubbele SPN's en zwakke certificaatmapping.

    .DESCRIPTION
        Leest Security-events 4768/4769 (encryptietype 0x17/0x18 RC4, 0x1/0x3 DES) voor zwakke
        Kerberos-encryptie, 4769 met fout 0x7 voor ontbrekende SPN's (NTLM-fallback), System-event
        11 (KDC) voor dubbele SPN's, en System-events 39/40/41 (Kdcsvc) voor zwakke
        certificaatkoppelingen. Vereist Kerberos- en foutauditing voor Service Ticket Operations;
        ontbrekende auditing levert "onbekend" op.

    .PARAMETER ComputerName
        Host om te meten. Standaard de lokale machine.

    .PARAMETER Since
        Vanaf welk tijdstip (UTC) gemeten wordt. Standaard de laatst gelezen RecordId.

    .OUTPUTS
        PSCustomObject[] met geaggregeerde Kerberos-bevindingen.

    .NOTES
        Fase 0. Alleen-lezen.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [datetime]$Since
    )

    throw "Get-HKKerberos is nog niet geïmplementeerd."
}
