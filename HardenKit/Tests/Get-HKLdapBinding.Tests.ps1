#Requires -Modules Pester

# Module importeren op scriptniveau: zie docs/LESSONS.md / de andere testbestanden voor waarom
# (InModuleScope heeft de module nodig tijdens Pester's Discovery-fase).
$script:ModuleRoot = Split-Path -Parent $PSScriptRoot
$script:ManifestPath = Join-Path $script:ModuleRoot 'HardenKit.psd1'
Import-Module $script:ManifestPath -Force

AfterAll {
    Remove-Module HardenKit -ErrorAction SilentlyContinue
}

Describe 'Get-HKLdapBinding' {

    Context 'alle bronnen leesbaar' {

        BeforeAll {
            # Fixtures inline als [pscustomobject] i.p.v. via een hulpfunctie: een losse
            # testfunctie op scriptniveau bleek niet betrouwbaar zichtbaar in BeforeAll/Mock
            # (bevestigd met een losse repro) — zie docs/LESSONS.md.
            Mock -ModuleName HardenKit Get-HKWinEvent {
                @(
                    [pscustomobject]@{ TimeCreatedUtc = [datetime]'2026-10-01T06:00:00Z'; EventRecordId = 10; EventId = 2889; Computer = 'dc01.contoso.com'; EventData = @{ Client = '10.0.0.5'; IdentityUser = 'jdoe' } }
                    [pscustomobject]@{ TimeCreatedUtc = [datetime]'2026-10-01T07:00:00Z'; EventRecordId = 11; EventId = 2889; Computer = 'dc01.contoso.com'; EventData = @{ Client = '10.0.0.5'; IdentityUser = 'jdoe' } }
                    [pscustomobject]@{ TimeCreatedUtc = [datetime]'2026-10-01T06:30:00Z'; EventRecordId = 12; EventId = 2889; Computer = 'dc01.contoso.com'; EventData = @{ Client = '10.0.0.9'; IdentityUser = 'svc_other' } }
                    [pscustomobject]@{ TimeCreatedUtc = [datetime]'2026-10-01T23:59:00Z'; EventRecordId = 13; EventId = 2887; Computer = 'dc01.contoso.com'; EventData = @{ Count = '42' } }
                    [pscustomobject]@{ TimeCreatedUtc = [datetime]'2026-10-01T08:00:00Z'; EventRecordId = 14; EventId = 3039; Computer = 'dc01.contoso.com'; EventData = @{ Client = '10.0.0.12' } }
                    [pscustomobject]@{ TimeCreatedUtc = [datetime]'2026-10-01T23:59:00Z'; EventRecordId = 15; EventId = 3041; Computer = 'dc01.contoso.com'; EventData = @{ Count = '7' } }
                )
            }
        }

        It 'markeert de collector als ok' {
            $result = Get-HKLdapBinding
            $result.Collectors.DirectoryServiceLog | Should -Be 'ok'
        }

        It 'aggregeert 2889 per client-IP en account onder ldap_signing' {
            $result = Get-HKLdapBinding
            $rows = @($result.Findings | Where-Object Measure -eq 'ldap_signing')
            $rows.Count | Should -Be 2

            $jdoe = $rows | Where-Object AccountName -eq 'jdoe'
            $jdoe.ClientIp | Should -Be '10.0.0.5'
            $jdoe.Count | Should -Be 2
            $jdoe.FirstSeenUtc | Should -Be ([datetime]'2026-10-01T06:00:00Z')
            $jdoe.LastSeenUtc | Should -Be ([datetime]'2026-10-01T07:00:00Z')
        }

        It 'neemt 3039 mee als ldap_channel_binding' {
            $result = Get-HKLdapBinding
            $row = $result.Findings | Where-Object Measure -eq 'ldap_channel_binding'
            $row.ClientIp | Should -Be '10.0.0.12'
            $row.Count | Should -Be 1
        }

        It 'zet 2887/3041 apart als dagsamenvatting, niet in Findings' {
            $result = Get-HKLdapBinding
            $result.SigningDailySummary.Count | Should -Be 1
            $result.SigningDailySummary[0].Count | Should -Be 42
            $result.ChannelBindingDailySummary.Count | Should -Be 1
            $result.ChannelBindingDailySummary[0].Count | Should -Be 7

            $result.Findings | Where-Object { $_.Measure -notin @('ldap_signing', 'ldap_channel_binding') } | Should -BeNullOrEmpty
        }

        It 'geeft de hoogste geziene RecordId terug' {
            $result = Get-HKLdapBinding
            $result.LastDirectoryServiceRecordId | Should -Be 15
        }
    }

    Context 'Directory Service-log niet leesbaar' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKWinEvent { throw 'toegang geweigerd' }
        }

        It 'breekt de run niet af en markeert de collector als onbekend' {
            { Get-HKLdapBinding -WarningAction SilentlyContinue } | Should -Not -Throw
            $result = Get-HKLdapBinding -WarningAction SilentlyContinue
            $result.Collectors.DirectoryServiceLog | Should -Be 'onbekend'
            $result.Findings.Count | Should -Be 0
            $result.LastDirectoryServiceRecordId | Should -BeNullOrEmpty
        }
    }

    Context 'geen events' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKWinEvent { @() }
        }

        It 'geeft lege resultaten terug zonder fouten' {
            $result = Get-HKLdapBinding
            $result.Collectors.DirectoryServiceLog | Should -Be 'ok'
            $result.Findings.Count | Should -Be 0
            $result.SigningDailySummary.Count | Should -Be 0
            $result.ChannelBindingDailySummary.Count | Should -Be 0
        }
    }

    Context 'ontbrekende Count-waarde in dagsamenvatting' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKWinEvent {
                @(
                    [pscustomobject]@{ TimeCreatedUtc = [datetime]'2026-10-01T23:59:00Z'; EventRecordId = 1; EventId = 2887; Computer = 'dc01.contoso.com'; EventData = @{} }
                )
            }
        }

        It 'valt terug op 0 in plaats van te gooien' {
            { Get-HKLdapBinding } | Should -Not -Throw
            (Get-HKLdapBinding).SigningDailySummary[0].Count | Should -Be 0
        }
    }
}
