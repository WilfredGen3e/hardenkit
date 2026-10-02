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

    Describe 'ConvertFrom-HKSetspnOutput' {
        # Pure parsing-logica, los van setspn.exe zelf, dus platformonafhankelijk testbaar.

        It 'geeft een lege lijst als er geen dubbele SPNs zijn' {
            $output = @(
                'Checking domain DC=contoso,DC=com'
                ''
                'Found 0 group of duplicate SPNs.'
            )
            $result = @($output | ConvertFrom-HKSetspnOutput)
            $result.Count | Should -Be 0
        }

        It 'herkent één groep dubbele SPNs met twee accounts' {
            $output = @(
                'Checking domain DC=contoso,DC=com'
                ''
                'Found 1 group of duplicate SPNs.'
                ''
                'HTTP/webserver.contoso.com'
                '        CN=WEBSVC1,OU=ServiceAccounts,DC=contoso,DC=com'
                '        CN=WEBSVC2,OU=ServiceAccounts,DC=contoso,DC=com'
                ''
                'operation completed successfully'
            )
            $result = @($output | ConvertFrom-HKSetspnOutput)
            $result.Count | Should -Be 1
            $result[0].Spn | Should -Be 'HTTP/webserver.contoso.com'
            $result[0].Accounts.Count | Should -Be 2
            $result[0].Accounts | Should -Contain 'CN=WEBSVC1,OU=ServiceAccounts,DC=contoso,DC=com'
            $result[0].Accounts | Should -Contain 'CN=WEBSVC2,OU=ServiceAccounts,DC=contoso,DC=com'
        }

        It 'herkent meerdere groepen dubbele SPNs' {
            $output = @(
                'Checking domain DC=contoso,DC=com'
                ''
                'Found 2 group of duplicate SPNs.'
                ''
                'HTTP/webserver.contoso.com'
                '        CN=WEBSVC1,OU=ServiceAccounts,DC=contoso,DC=com'
                '        CN=WEBSVC2,OU=ServiceAccounts,DC=contoso,DC=com'
                ''
                'HOST/legacyprinter'
                '        CN=PRN01,OU=Computers,DC=contoso,DC=com'
                '        CN=PRN02,OU=Computers,DC=contoso,DC=com'
                ''
                'operation completed successfully'
            )
            $result = @($output | ConvertFrom-HKSetspnOutput)
            $result.Count | Should -Be 2
            $result[1].Spn | Should -Be 'HOST/legacyprinter'
        }
    }

    Describe 'Remote guard op de nieuwe Get-HKBaseline-helpers' {
        # Expliciet op de foutmelding gecontroleerd, zodat een "command not found" (bv. omdat
        # de functie per ongeluk niet in module-scope draait) niet per ongeluk als geslaagde
        # -Throw telt.

        It 'Get-HKOperatingSystemInfo weigert een andere computer dan de lokale' {
            { Get-HKOperatingSystemInfo -ComputerName 'ANDERE-HOST' } | Should -Throw -ExpectedMessage '*alleen de lokale machine*'
        }

        It 'Get-HKDomainControllerInfo weigert een andere computer dan de lokale' {
            { Get-HKDomainControllerInfo -ComputerName 'ANDERE-HOST' } | Should -Throw -ExpectedMessage '*alleen de lokale machine*'
        }

        It 'Get-HKDuplicateSpn weigert een andere computer dan de lokale' {
            { Get-HKDuplicateSpn -ComputerName 'ANDERE-HOST' } | Should -Throw -ExpectedMessage '*alleen de lokale machine*'
        }

        It 'Get-HKKrbtgtAge weigert een andere computer dan de lokale' {
            { Get-HKKrbtgtAge -ComputerName 'ANDERE-HOST' } | Should -Throw -ExpectedMessage '*alleen de lokale machine*'
        }

        It 'Get-HKTimeSource weigert een andere computer dan de lokale' {
            { Get-HKTimeSource -ComputerName 'ANDERE-HOST' } | Should -Throw -ExpectedMessage '*alleen de lokale machine*'
        }

        It 'Get-HKSysvolReplicationInfo weigert een andere computer dan de lokale' {
            { Get-HKSysvolReplicationInfo -ComputerName 'ANDERE-HOST' } | Should -Throw -ExpectedMessage '*alleen de lokale machine*'
        }

        It 'Get-HKSmbNtlmConfig weigert een andere computer dan de lokale' {
            { Get-HKSmbNtlmConfig -ComputerName 'ANDERE-HOST' } | Should -Throw -ExpectedMessage '*alleen de lokale machine*'
        }
    }
}

Describe 'Get-HKBaseline' {

    Context 'alle bronnen leesbaar' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKOperatingSystemInfo {
                [pscustomobject]@{ Caption = 'Windows Server 2022 Datacenter'; Version = '10.0.20348'; BuildNumber = '20348' }
            }
            Mock -ModuleName HardenKit Get-HKDomainControllerInfo {
                [pscustomobject]@{ DomainControllers = @('dc01.contoso.com', 'dc02.contoso.com'); PdcEmulator = 'dc01.contoso.com'; IsPdcEmulator = $true }
            }
            Mock -ModuleName HardenKit Get-HKDuplicateSpn { @() }
            Mock -ModuleName HardenKit Get-HKKrbtgtAge {
                [pscustomobject]@{ PasswordLastSetUtc = (Get-Date).ToUniversalTime().AddDays(-90); AgeDays = 90 }
            }
            Mock -ModuleName HardenKit Get-HKTimeSource { [pscustomobject]@{ Source = 'Free-running System Clock' } }
            Mock -ModuleName HardenKit Get-HKSysvolReplicationInfo { [pscustomobject]@{ Technology = 'DFSR'; Ready = $true } }
            Mock -ModuleName HardenKit Get-HKSmbNtlmConfig {
                [pscustomobject]@{
                    LmCompatibilityLevel         = 5
                    RestrictSendingNTLMTraffic   = 1
                    RestrictReceivingNTLMTraffic = 1
                    Smb1Enabled                  = $false
                    PrintSpoolerStatus           = 'Running'
                    PrintSpoolerStartType        = 'Automatic'
                }
            }
            Mock -ModuleName HardenKit Get-HKLdapAuditSettings {
                [pscustomobject]@{ LdapServerIntegrity = 2; DiagnosticsLevel = 2; ChannelBindingMode = 1 }
            }
            Mock -ModuleName HardenKit Get-HKSecurityLogInfo {
                [pscustomobject]@{ MaximumSizeInBytes = 1GB; RecordCount = 500000; OldestRecordUtc = (Get-Date).ToUniversalTime().AddDays(-35); NewestRecordUtc = (Get-Date).ToUniversalTime() }
            }
        }

        It 'markeert alle collectors als ok' {
            $result = Get-HKBaseline
            foreach ($prop in $result.Collectors.PSObject.Properties) {
                $prop.Value | Should -Be 'ok'
            }
        }

        It 'geeft de resultaten van elke bron door' {
            $result = Get-HKBaseline
            $result.OperatingSystem.Caption | Should -Be 'Windows Server 2022 Datacenter'
            $result.DomainControllers.DomainControllers.Count | Should -Be 2
            $result.DuplicateSpn.Count | Should -Be 0
            $result.Krbtgt.AgeDays | Should -Be 90
            $result.TimeSource.Source | Should -Be 'Free-running System Clock'
            $result.Sysvol.Technology | Should -Be 'DFSR'
            $result.SmbNtlmConfig.Smb1Enabled | Should -BeFalse
            $result.LdapAudit.LdapServerIntegrity | Should -Be 2
            $result.SecurityLog.RecordCount | Should -Be 500000
        }
    }

    Context 'krbtgt niet leesbaar, overige bronnen wel' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKOperatingSystemInfo {
                [pscustomobject]@{ Caption = 'Windows Server 2022 Datacenter'; Version = '10.0.20348'; BuildNumber = '20348' }
            }
            Mock -ModuleName HardenKit Get-HKDomainControllerInfo {
                [pscustomobject]@{ DomainControllers = @('dc01.contoso.com'); PdcEmulator = 'dc01.contoso.com'; IsPdcEmulator = $true }
            }
            Mock -ModuleName HardenKit Get-HKDuplicateSpn { @() }
            Mock -ModuleName HardenKit Get-HKKrbtgtAge { throw 'toegang geweigerd' }
            Mock -ModuleName HardenKit Get-HKTimeSource { [pscustomobject]@{ Source = 'Free-running System Clock' } }
            Mock -ModuleName HardenKit Get-HKSysvolReplicationInfo { [pscustomobject]@{ Technology = 'DFSR'; Ready = $true } }
            Mock -ModuleName HardenKit Get-HKSmbNtlmConfig {
                [pscustomobject]@{ LmCompatibilityLevel = 5; RestrictSendingNTLMTraffic = 1; RestrictReceivingNTLMTraffic = 1; Smb1Enabled = $false; PrintSpoolerStatus = 'Running'; PrintSpoolerStartType = 'Automatic' }
            }
            Mock -ModuleName HardenKit Get-HKLdapAuditSettings {
                [pscustomobject]@{ LdapServerIntegrity = 2; DiagnosticsLevel = 2; ChannelBindingMode = 1 }
            }
            Mock -ModuleName HardenKit Get-HKSecurityLogInfo {
                [pscustomobject]@{ MaximumSizeInBytes = 1GB; RecordCount = 1; OldestRecordUtc = $null; NewestRecordUtc = $null }
            }
        }

        It 'breekt de run niet af en markeert alleen Krbtgt als onbekend' {
            { Get-HKBaseline -WarningAction SilentlyContinue } | Should -Not -Throw
            $result = Get-HKBaseline -WarningAction SilentlyContinue
            $result.Collectors.Krbtgt | Should -Be 'onbekend'
            $result.Krbtgt | Should -BeNullOrEmpty
            $result.Collectors.OperatingSystem | Should -Be 'ok'
            $result.Collectors.LdapAudit | Should -Be 'ok'
        }
    }
}
