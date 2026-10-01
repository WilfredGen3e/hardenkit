# Lessons learned — HardenKit

Doel: valkuilen die we al eens tegenkwamen, zodat we ze niet opnieuw ontdekken. **Check dit
bestand voor je aan een nieuwe collector begint.** Voeg een item toe zodra je een niet-triviale
bug fixt (niet voor typo's of iets dat de linter al vangt) — kort: wat ging er mis, waarom, en
de fix.

## PowerShell-taalvalkuilen

### `[string]$Param = $env:X` vergelijken met het ongetypeerde `$env:X`
**Wat:** op een host zonder de env-var (bv. `$env:COMPUTERNAME` op macOS) wordt een getypeerd
`[string]$ComputerName = $env:COMPUTERNAME`-default `''`, maar `$env:COMPUTERNAME` zelf blijft
`$null`. `'' -eq $null` is `False` in PowerShell, dus `if ($ComputerName -ne $env:COMPUTERNAME)`
gooit ten onrechte.
**Fix:** cast beide kanten expliciet: `if ($ComputerName -ne [string]$env:COMPUTERNAME)`.
**Waar gezien:** alle "alleen lokale machine"-guards (Get-HKAuditPolicy,
Get-HKNtlmAuditSetting, Get-HKLdapAuditSettings, Get-HKSecurityLogInfo, Test-HKAuditConfig, en
alle Get-HKBaseline-helpers).

### De "comma-trick" (`, $array`) om array-uitpakken te voorkomen, faalt binnen Pester's `InModuleScope`
**Wat:** `, $results.ToArray()` als laatste statement, bedoeld om te voorkomen dat PowerShell
een 0- of 1-element array uitrolt op de pipeline, gaf binnen Pester's `InModuleScope` een
dubbel-geneste array terug (empirisch vastgesteld met een losse repro buiten de module, niet
uit documentatie af te leiden).
**Fix:** geen comma-trick gebruiken; functies laten gewoon losse objecten streamen
(`$results.ToArray()` zónder comma), en de aanroeper wrapt zelf met `@(...)` voor een
betrouwbare array.
**Algemenere regel (geverifieerd, geldt los van de comma-trick):** een functie waarvan de
uitvoer naar 0 objecten enumereert, geeft bij *directe* toekenning (`$x = Get-Foo`, geen pipe)
altijd `$null` terug — ook als de functie zelf intern al netjes `@(...)` gebruikt
(bv. `@($events | ForEach-Object {...})` als laatste statement). De `@(...)` binnen de
functie-body beschermt de aanroeper dus niet. Enige betrouwbare fix: wrap de *aanroep*, nooit
(alleen) de functie-body: `$x = @(Get-Foo)`. Pas dit overal toe waar een functie 0..N objecten
kan teruggeven en de aanroeper `.Count` of een foreach op het resultaat doet.
**Waar gezien:** `ConvertFrom-HKSetspnOutput` en het gebruik van `Get-HKDuplicateSpn` in
`Get-HKBaseline`.

### Lege string in een pipeline naar een `[string[]]`-parameter
**Wat:** `[AllowEmptyCollection()]` staat een lege *array* toe, maar niet een los element dat
een lege string is binnen een niet-lege array die via de pipeline binnenkomt. Testinvoer met
blanco regels (zoals echte `auditpol`/`setspn`-uitvoer die blanco regels bevat) brak hierop met
"Cannot bind argument ... because it is an empty string."
**Fix:** `[AllowEmptyString()]` toevoegen naast `[AllowEmptyCollection()]`.
**Waar gezien:** `ConvertFrom-HKAuditPolicyCsv`, `ConvertFrom-HKSetspnOutput`.

## Testconventies (ter voorkoming van vals-positieve tests)

### Private functies buiten `InModuleScope` aanroepen geeft vals-positieve `-Throw`-asserts
**Wat:** een eerste testopzet riep private (niet-geëxporteerde) functies rechtstreeks aan in een
testscript buiten de module. PowerShell gooit dan "command not found" — en dat laat
`Should -Throw` zonder `-ExpectedMessage` slagen, ook al is de eigenlijke guard-logica nooit
uitgevoerd.
**Fix:** test private functies altijd binnen `InModuleScope <ModuleName> { ... }`, én gebruik
`-ExpectedMessage` bij `Should -Throw` zodat een verkeerde foutoorzaak niet per ongeluk als
geslaagde test telt.
**Waar gezien:** `Test-HKAuditConfig.Tests.ps1` (herschreven), toegepast in
`Get-HKBaseline.Tests.ps1`.

## Werkwijze voor Windows-only logica op een macOS-ontwikkelmachine

Pester-tests draaien lokaal op macOS (pwsh); de module zelf draait alleen op Windows Server
DC's. Daarom splitsen we Windows-only logica (CIM, registry, `auditpol.exe`, `setspn.exe`,
`w32tm.exe`, ADSI/AD) consequent in twee lagen:

1. Een dunne I/O-laag die de externe tool/cmdlet aanroept (bv. `Get-HKAuditPolicy`,
   `Get-HKDuplicateSpn`). Hiervoor volstaat een cross-platform remote-guard-test plus latere
   handmatige validatie op een echte DC.
2. Een pure parsing-/logicalaag zonder Windows-afhankelijkheid (bv.
   `ConvertFrom-HKAuditPolicyCsv`, `ConvertFrom-HKSetspnOutput`). Deze laag krijgt de
   uitgebreide tests, want die kunnen écht overal draaien.

## Nog niet op een echte DC geverifieerd

Onderstaande zijn aannames op basis van Microsoft-documentatie, niet getest tegen een live DC.
Zie ook de open vragen in `CLAUDE.md`.

- Registrynamen: `AuditNTLMInDomain`, `16 LDAP Interface Events`, `LdapEnforceChannelBinding`,
  `LDAPServerIntegrity`, `RestrictSendingNTLMTraffic`, `RestrictReceivingNTLMTraffic`,
  `SysvolReady`.
- Engelstalige tool-uitvoer die we parsen: `auditpol.exe` (`Success`/`Failure`/
  `Success and Failure`/`No Auditing`), `setspn.exe -X`. Op een Nederlandstalige Windows-
  installatie kan deze tekst afwijken.
