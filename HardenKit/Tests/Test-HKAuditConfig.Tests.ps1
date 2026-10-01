#Requires -Modules Pester

# Module importeren op scriptniveau (niet in BeforeAll): InModuleScope hieronder heeft de
# module nodig tijdens Pester's Discovery-fase, die vóór BeforeAll/Run-blokken draait.
$script:ModuleRoot = Split-Path -Parent $PSScriptRoot
$script:ManifestPath = Join-Path $script:ModuleRoot 'HardenKit.psd1'
Import-Module $script:ManifestPath -Force

AfterAll {
    Remove-Module HardenKit -ErrorAction SilentlyContinue
}

InModuleScope HardenKit {

    Describe 'ConvertFrom-HKAuditPolicyCsv' {
        # Pure parsing-logica, los van auditpol.exe zelf, dus platformonafhankelijk testbaar.
        # Private functie: moet binnen InModuleScope aangeroepen worden, anders is ze niet
        # zichtbaar (en zou een "command not found" ten onrechte als geslaagde -Throw tellen).

        It 'herkent "Success and Failure"' {
            $csv = @(
                '"Machine Name","Policy Target","Subcategory","Subcategory GUID","Inclusion Setting","Exclusion Setting"'
                '"DC01","System","Logon","{0CCE9215-69AE-11D9-BED3-505054503030}","Success and Failure",""'
            )
            $result = $csv | ConvertFrom-HKAuditPolicyCsv
            $result.Success | Should -BeTrue
            $result.Failure | Should -BeTrue
        }

        It 'herkent "Success"' {
            $csv = @(
                '"Machine Name","Policy Target","Subcategory","Subcategory GUID","Inclusion Setting","Exclusion Setting"'
                '"DC01","System","Credential Validation","{...}","Success",""'
            )
            $result = $csv | ConvertFrom-HKAuditPolicyCsv
            $result.Success | Should -BeTrue
            $result.Failure | Should -BeFalse
        }

        It 'herkent "Failure"' {
            $csv = @(
                '"Machine Name","Policy Target","Subcategory","Subcategory GUID","Inclusion Setting","Exclusion Setting"'
                '"DC01","System","Kerberos Service Ticket Operations","{...}","Failure",""'
            )
            $result = $csv | ConvertFrom-HKAuditPolicyCsv
            $result.Success | Should -BeFalse
            $result.Failure | Should -BeTrue
        }

        It 'herkent "No Auditing"' {
            $csv = @(
                '"Machine Name","Policy Target","Subcategory","Subcategory GUID","Inclusion Setting","Exclusion Setting"'
                '"DC01","System","Logon","{...}","No Auditing",""'
            )
            $result = $csv | ConvertFrom-HKAuditPolicyCsv
            $result.Success | Should -BeFalse
            $result.Failure | Should -BeFalse
        }

        It 'gooit een fout bij lege invoer' {
            { , @() | ConvertFrom-HKAuditPolicyCsv } | Should -Throw
        }
    }

    Describe 'Remote guard op Get-HKAuditPolicy / Get-HKNtlmAuditSetting / Get-HKLdapAuditSettings' {
        # De Windows-specifieke I/O (auditpol.exe, registry) wordt hier niet getest, maar de
        # guard tegen remote gebruik is pure PowerShell-logica en dus overal testbaar. Expliciet
        # op de foutmelding gecontroleerd, zodat een "command not found" (bv. omdat de functie
        # per ongeluk niet in module-scope draait) niet per ongeluk als geslaagde -Throw telt.

        It 'Get-HKAuditPolicy weigert een andere computer dan de lokale' {
            { Get-HKAuditPolicy -ComputerName 'ANDERE-HOST' } | Should -Throw -ExpectedMessage '*alleen de lokale machine*'
        }

        It 'Get-HKNtlmAuditSetting weigert een andere computer dan de lokale' {
            { Get-HKNtlmAuditSetting -ComputerName 'ANDERE-HOST' } | Should -Throw -ExpectedMessage '*alleen de lokale machine*'
        }

        It 'Get-HKLdapAuditSettings weigert een andere computer dan de lokale' {
            { Get-HKLdapAuditSettings -ComputerName 'ANDERE-HOST' } | Should -Throw -ExpectedMessage '*alleen de lokale machine*'
        }
    }
}

Describe 'Test-HKAuditConfig' {

    Context 'alle bronnen leesbaar' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKAuditPolicy {
                @{
                    'Logon'                               = [pscustomobject]@{ Success = $true; Failure = $true }
                    'Credential Validation'                = [pscustomobject]@{ Success = $true; Failure = $false }
                    'Kerberos Authentication Service'      = [pscustomobject]@{ Success = $true; Failure = $false }
                    'Kerberos Service Ticket Operations'   = [pscustomobject]@{ Success = $true; Failure = $true }
                }
            }
            Mock -ModuleName HardenKit Get-HKSecurityLogInfo {
                [pscustomobject]@{
                    MaximumSizeInBytes = 1GB
                    RecordCount        = 500000
                    OldestRecordUtc    = (Get-Date).ToUniversalTime().AddDays(-35)
                    NewestRecordUtc    = (Get-Date).ToUniversalTime()
                }
            }
            Mock -ModuleName HardenKit Get-HKNtlmAuditSetting {
                [pscustomobject]@{ Enabled = $true; RawValue = 7 }
            }
            Mock -ModuleName HardenKit Get-HKLdapAuditSettings {
                [pscustomobject]@{ DiagnosticsLevel = 2; ChannelBindingMode = 1 }
            }
        }

        It 'markeert alle collectors als ok' {
            $result = Test-HKAuditConfig
            $result.Collectors.AuditPolicy | Should -Be 'ok'
            $result.Collectors.SecurityLog | Should -Be 'ok'
            $result.Collectors.NtlmAudit | Should -Be 'ok'
            $result.Collectors.LdapAudit | Should -Be 'ok'
        }

        It 'zet alle maatregelen met voldane voorwaarde op Ok' {
            $result = Test-HKAuditConfig
            $byMeasure = @{}
            foreach ($m in $result.Measures) { $byMeasure[$m.Measure] = $m }

            $byMeasure['ntlmv1'].Status | Should -Be 'Ok'
            $byMeasure['ntlm_8004'].Status | Should -Be 'Ok'
            $byMeasure['ntlm_4776'].Status | Should -Be 'Ok'
            $byMeasure['ldap_signing'].Status | Should -Be 'Ok'
            $byMeasure['ldap_channel_binding'].Status | Should -Be 'Ok'
            $byMeasure['kerberos_rc4_des'].Status | Should -Be 'Ok'
            $byMeasure['missing_spn'].Status | Should -Be 'Ok'
            $byMeasure['lockouts'].Status | Should -Be 'Ok'
        }

        It 'zet maatregelen zonder voorwaarde altijd op Ok' {
            $result = Test-HKAuditConfig
            ($result.Measures | Where-Object Measure -eq 'replication').Status | Should -Be 'Ok'
        }

        It 'geeft de Security-log informatie door' {
            $result = Test-HKAuditConfig
            $result.SecurityLog.RecordCount | Should -Be 500000
        }
    }

    Context 'auditpol niet leesbaar' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKAuditPolicy { throw 'toegang geweigerd' }
            Mock -ModuleName HardenKit Get-HKSecurityLogInfo {
                [pscustomobject]@{ MaximumSizeInBytes = 1GB; RecordCount = 1; OldestRecordUtc = $null; NewestRecordUtc = $null }
            }
            Mock -ModuleName HardenKit Get-HKNtlmAuditSetting { [pscustomobject]@{ Enabled = $true; RawValue = 7 } }
            Mock -ModuleName HardenKit Get-HKLdapAuditSettings { [pscustomobject]@{ DiagnosticsLevel = 2; ChannelBindingMode = 1 } }
        }

        It 'markeert de AuditPolicy-collector als onbekend, zonder de run af te breken' {
            { Test-HKAuditConfig -WarningAction SilentlyContinue } | Should -Not -Throw
            $result = Test-HKAuditConfig -WarningAction SilentlyContinue
            $result.Collectors.AuditPolicy | Should -Be 'onbekend'
        }

        It 'zet auditpol-afhankelijke maatregelen op Onbekend' {
            $result = Test-HKAuditConfig -WarningAction SilentlyContinue
            $byMeasure = @{}
            foreach ($m in $result.Measures) { $byMeasure[$m.Measure] = $m }

            $byMeasure['ntlmv1'].Status | Should -Be 'Onbekend'
            $byMeasure['missing_spn'].Status | Should -Be 'Onbekend'
        }

        It 'laat maatregelen die niet van auditpol afhangen onverstoord' {
            $result = Test-HKAuditConfig -WarningAction SilentlyContinue
            $byMeasure = @{}
            foreach ($m in $result.Measures) { $byMeasure[$m.Measure] = $m }

            $byMeasure['ntlm_8004'].Status | Should -Be 'Ok'
            $byMeasure['ldap_signing'].Status | Should -Be 'Ok'
        }
    }

    Context 'auditpol leesbaar maar auditing staat uit' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKAuditPolicy {
                @{
                    'Logon'                               = [pscustomobject]@{ Success = $false; Failure = $false }
                    'Credential Validation'                = [pscustomobject]@{ Success = $false; Failure = $false }
                    'Kerberos Authentication Service'      = [pscustomobject]@{ Success = $false; Failure = $false }
                    'Kerberos Service Ticket Operations'   = [pscustomobject]@{ Success = $false; Failure = $false }
                }
            }
            Mock -ModuleName HardenKit Get-HKSecurityLogInfo {
                [pscustomobject]@{ MaximumSizeInBytes = 1GB; RecordCount = 1; OldestRecordUtc = $null; NewestRecordUtc = $null }
            }
            Mock -ModuleName HardenKit Get-HKNtlmAuditSetting { [pscustomobject]@{ Enabled = $false; RawValue = $null } }
            Mock -ModuleName HardenKit Get-HKLdapAuditSettings { [pscustomobject]@{ DiagnosticsLevel = 0; ChannelBindingMode = 0 } }
        }

        It 'zet maatregelen op NietVoldaan, niet op Onbekend' {
            $result = Test-HKAuditConfig
            $byMeasure = @{}
            foreach ($m in $result.Measures) { $byMeasure[$m.Measure] = $m }

            $byMeasure['ntlmv1'].Status | Should -Be 'NietVoldaan'
            $byMeasure['ntlm_8004'].Status | Should -Be 'NietVoldaan'
            $byMeasure['ldap_signing'].Status | Should -Be 'NietVoldaan'
        }
    }
}
