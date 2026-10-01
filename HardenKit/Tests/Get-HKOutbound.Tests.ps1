#Requires -Modules Pester

$script:ModuleRoot = Split-Path -Parent $PSScriptRoot
$script:ManifestPath = Join-Path $script:ModuleRoot 'HardenKit.psd1'
Import-Module $script:ManifestPath -Force

AfterAll {
    Remove-Module HardenKit -ErrorAction SilentlyContinue
}

InModuleScope HardenKit {
    Describe 'Remote guard op Get-HKOutboundConnections' {
        It 'weigert een andere computer dan de lokale' {
            { Get-HKOutboundConnections -ComputerName 'ANDERE-HOST' } | Should -Throw -ExpectedMessage '*alleen de lokale machine*'
        }
    }
}

Describe 'Get-HKOutbound' {

    Context 'verbindingen leesbaar' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKOutboundConnections {
                @(
                    [pscustomobject]@{ Measure = 'outbound'; AccountName = $null; AccountSid = $null; ClientFqdn = 'update.microsoft.com'; ClientIp = '20.0.0.1'; Target = 'svchost'; TimeCreatedUtc = (Get-Date).ToUniversalTime() }
                    [pscustomobject]@{ Measure = 'outbound'; AccountName = $null; AccountSid = $null; ClientFqdn = $null; ClientIp = '10.0.0.99'; Target = 'HardenKitAgent'; TimeCreatedUtc = (Get-Date).ToUniversalTime() }
                )
            }
        }

        It 'markeert de collector als ok' {
            $result = Get-HKOutbound
            $result.Collectors.Connections | Should -Be 'ok'
        }

        It 'aggregeert per proces en bestemming' {
            $result = Get-HKOutbound
            $result.Findings.Count | Should -Be 2
            ($result.Findings | Where-Object Target -eq 'svchost').ClientFqdn | Should -Be 'update.microsoft.com'
            ($result.Findings | Where-Object Target -eq 'HardenKitAgent').ClientIp | Should -Be '10.0.0.99'
        }

        It 'laat AccountName/AccountSid altijd leeg' {
            $result = Get-HKOutbound
            $result.Findings | ForEach-Object {
                $_.AccountName | Should -BeNullOrEmpty
                $_.AccountSid | Should -BeNullOrEmpty
            }
        }
    }

    Context 'verbindingen niet leesbaar' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKOutboundConnections { throw 'toegang geweigerd' }
        }

        It 'breekt de run niet af en markeert de collector als onbekend' {
            { Get-HKOutbound -WarningAction SilentlyContinue } | Should -Not -Throw
            $result = Get-HKOutbound -WarningAction SilentlyContinue
            $result.Collectors.Connections | Should -Be 'onbekend'
            $result.Findings.Count | Should -Be 0
        }
    }

    Context 'geen actieve verbindingen' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKOutboundConnections { @() }
        }

        It 'geeft lege Findings terug zonder fouten' {
            $result = Get-HKOutbound
            $result.Findings.Count | Should -Be 0
        }
    }
}
