function Get-HKNtlmUsage {
    <#
    .SYNOPSIS
        Meet NTLMv1/LM-gebruik en NTLM-authenticatie, inclusief NTLM naar IP of alias.

    .DESCRIPTION
        Leest Security-event 4624 (LmPackageName) voor NTLMv1/LM, NTLM/Operational-event 8004
        voor NTLM-gebruik in het domein, en Security-event 4776 voor NTLM-credentialvalidaties.
        Aggregeert per client (FQDN/IP), account en doelserver. Vereist dat logon-auditing en
        NTLM-audit aanstaan (zie Test-HKAuditConfig); ontbrekende auditing levert "onbekend" op.

    .PARAMETER ComputerName
        Host om te meten. Standaard de lokale machine.

    .PARAMETER Since
        Vanaf welk tijdstip (UTC) gemeten wordt. Standaard de laatst gelezen RecordId.

    .OUTPUTS
        PSCustomObject[] met geaggregeerde NTLM-bevindingen.

    .NOTES
        Fase 0. Alleen-lezen.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [datetime]$Since
    )

    throw "Get-HKNtlmUsage is nog niet geïmplementeerd."
}
