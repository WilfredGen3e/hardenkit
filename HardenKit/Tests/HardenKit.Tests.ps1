#Requires -Modules Pester

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    $script:ManifestPath = Join-Path $ModuleRoot 'HardenKit.psd1'
    Import-Module $script:ManifestPath -Force
}

AfterAll {
    Remove-Module HardenKit -ErrorAction SilentlyContinue
}

Describe 'HardenKit module' {

    It 'heeft een geldig manifest' {
        { Test-ModuleManifest -Path $script:ManifestPath -ErrorAction Stop } | Should -Not -Throw
    }

    It 'exporteert precies de verwachte publieke functies' {
        $expected = @(
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
        $exported = (Get-Command -Module HardenKit).Name
        $exported | Sort-Object | Should -Be ($expected | Sort-Object)
    }

    It 'exporteert geen private helperfuncties' {
        (Get-Command -Module HardenKit -Name 'Get-HKHostRole' -ErrorAction SilentlyContinue) | Should -BeNullOrEmpty
    }
}

Describe 'Get-HKHostRole' {
    # Get-CimInstance bestaat alleen op Windows (CimCmdlets); HardenKit draait uitsluitend
    # op Windows DC's/member servers, dus deze tests slaan over op andere platformen.

    It 'geeft DC terug voor DomainRole 4 of 5' -Skip:(-not $IsWindows) {
        Mock -ModuleName HardenKit Get-CimInstance { [pscustomobject]@{ DomainRole = 5 } }
        Get-HKHostRole | Should -Be 'DC'
    }

    It 'geeft MemberServer terug voor DomainRole 3' -Skip:(-not $IsWindows) {
        Mock -ModuleName HardenKit Get-CimInstance { [pscustomobject]@{ DomainRole = 3 } }
        Get-HKHostRole | Should -Be 'MemberServer'
    }

    It 'geeft Other terug voor overige rollen' -Skip:(-not $IsWindows) {
        Mock -ModuleName HardenKit Get-CimInstance { [pscustomobject]@{ DomainRole = 0 } }
        Get-HKHostRole | Should -Be 'Other'
    }
}
