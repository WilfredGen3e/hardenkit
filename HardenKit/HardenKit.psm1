#Requires -Version 5.1

# Root module: dot-sourcet alle Private/ en Public/ functies en exporteert alleen de Public API.
# HardenKit is alleen-lezen; er wordt hier niets aan het domein gewijzigd.

$private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -ErrorAction SilentlyContinue)
$public  = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -ErrorAction SilentlyContinue)

foreach ($file in @($private + $public)) {
    try {
        . $file.FullName
    }
    catch {
        throw "HardenKit: kon $($file.FullName) niet laden: $_"
    }
}

Export-ModuleMember -Function $public.BaseName
