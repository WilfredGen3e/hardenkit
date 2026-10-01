@{
    RootModule        = 'HardenKit.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '63b377f6-3344-43d7-a7aa-f357a359f7d1'
    Author            = 'Stefan Siemerink'
    CompanyName       = ''
    Copyright         = '(c) Stefan Siemerink. All rights reserved.'
    Description       = 'Alleen-lezen PowerShell-module die meet wat er breekt bij het hardenen van on-premises Active Directory.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Test-HKAuditConfig',
        'Get-HKBaseline',
        'Get-HKNtlmUsage',
        'Get-HKLdapBinding',
        'Get-HKKerberos',
        'Get-HKDomainHealth',
        'Get-HKOutbound',
        'Export-HKData',
        'New-HKReport'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('ActiveDirectory', 'Security', 'Hardening', 'MSP')
            ProjectUri = 'https://github.com/WilfredGen3e/hardenkit'
        }
    }
}
