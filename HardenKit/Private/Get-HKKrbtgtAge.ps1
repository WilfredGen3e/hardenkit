function Get-HKKrbtgtAge {
    <#
    .SYNOPSIS
        Bepaalt de leeftijd van het krbtgt-wachtwoord.

    .DESCRIPTION
        Zoekt het krbtgt-account via ADSI (System.DirectoryServices, geen ActiveDirectory-module
        nodig) en leest pwdLastSet uit.

    .PARAMETER ComputerName
        Host om te bevragen. Alleen de lokale machine wordt ondersteund.

    .OUTPUTS
        PSCustomObject met PasswordLastSetUtc ([datetime]) en AgeDays ([int]).

    .NOTES
        Fase 0. Alleen-lezen. Vereist leesrechten op het krbtgt-object (standaard voor
        Domain Admins/SYSTEM op een DC).
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKKrbtgtAge ondersteunt alleen de lokale machine."
    }

    $rootDse = [ADSI]'LDAP://RootDSE'
    $defaultNamingContext = $rootDse.defaultNamingContext[0]

    $searcher = [adsisearcher]'(&(objectClass=user)(sAMAccountName=krbtgt))'
    $searcher.SearchRoot = [ADSI]"LDAP://$defaultNamingContext"
    $searcher.PropertiesToLoad.Add('pwdLastSet') | Out-Null

    $result = $searcher.FindOne()
    if (-not $result) {
        throw "krbtgt-account niet gevonden onder $defaultNamingContext."
    }

    $pwdLastSetRaw = $result.Properties['pwdlastset'][0]
    $pwdLastSetUtc = [datetime]::FromFileTimeUtc($pwdLastSetRaw)

    [pscustomobject]@{
        PasswordLastSetUtc = $pwdLastSetUtc
        AgeDays            = [int]((Get-Date).ToUniversalTime() - $pwdLastSetUtc).TotalDays
    }
}
