function Get-HKNtlmAuditSetting {
    <#
    .SYNOPSIS
        Leest of "Audit NTLM authentication in this domain" aanstaat (basis voor event 8004).

    .DESCRIPTION
        Leest de registrywaarde AuditNTLMInDomain onder
        HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters, die hoort bij het GPO-item
        "Network security: Restrict NTLM: Audit NTLM authentication in this domain". Deze
        instelling is alleen relevant op domain controllers. Een ontbrekende waarde betekent
        dat de instelling niet geconfigureerd is (dus niet aan).

    .PARAMETER ComputerName
        Host om te bevragen. Alleen de lokale machine wordt ondersteund: registry-remoting is
        hier bewust uitgesloten.

    .OUTPUTS
        PSCustomObject met Enabled ([bool]) en RawValue ([int] of $null).

    .NOTES
        Fase 0. Alleen-lezen. Registrynaam/-pad nog te verifiëren op een echte DC
        (zie open vragen in CLAUDE.md).
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKNtlmAuditSetting ondersteunt alleen de lokale machine (registry-remoting is hier bewust uitgesloten)."
    }

    $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    $value = (Get-ItemProperty -Path $path -Name 'AuditNTLMInDomain' -ErrorAction SilentlyContinue).AuditNTLMInDomain

    [pscustomobject]@{
        Enabled  = [bool]($value -and $value -ne 0)
        RawValue = $value
    }
}
