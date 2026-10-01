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

**Keerzijde, net zo belangrijk:** `@($null)` (of `@($iets.Dat.Null.Is)`) is géén lege array —
het is een array mét één element, en dat element is `$null`. Dus `@(...)` rond een mogelijk
`$null`-waarde "repareert" niets; een `foreach` daarover loopt gewoon één keer met `$row = $null`.
Check expliciet op `$null`/`if ($x) { ... }` vóórdat je `@($x.Property)` doet, in plaats van te
vertrouwen op `@(...)` alleen. **Samengevat: `@(...)` lost het "0 objecten → $null"-probleem bij
een aanroep op, maar maakt een losse `$null`-waarde niet tot een lege array — twee verschillende
problemen, twee verschillende fixes.**
**Waar gezien:** `Export-HKData` crashte op een falende collector of een niet-DC-rol, omdat
`@($ntlmUsage.Findings)` bij `$ntlmUsage -eq $null` een array met één `$null`-element gaf in
plaats van leeg — opgelost met een expliciete `if ($ntlmUsage) { ... }` vóór de `foreach`.
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

### Een losse testhulpfunctie op scriptniveau is niet betrouwbaar zichtbaar in `BeforeAll`/`Mock`
**Wat:** een `function New-HKTestEvent { ... }` bovenaan het testbestand (buiten
`InModuleScope`, gewoon op scriptniveau) gaf "command not found" zodra die werd aangeroepen
vanuit een `BeforeAll`-blok of een `Mock`-scriptblock — ook toen die niet eens over de
module-grens ging. Oorzaak niet volledig doorgrond; empirisch vastgesteld, niet aangenomen.
**Fix:** geen losse testhulpfunctie voor fixtures; bouw fixture-objecten inline als
`[pscustomobject]@{...}` (zoals in `Get-HKNtlmUsage.Tests.ps1`), of bouw de data op in een
variabele vlak vóór de `Mock`-aanroep en laat de mock-scriptblock alleen die variabele
teruggeven (closures over variabelen werken wél betrouwbaar).
**Waar gezien:** eerste opzet van `Get-HKLdapBinding.Tests.ps1`.

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

## Nog niet op een echte DC geverifieerd — pilot-testlijst

Onderstaande zijn aannames op basis van Microsoft-documentatie, niet getest tegen een live DC.
**Dit is de lijst om af te werken zodra de eerste pilot draait** (zie ook de open vragen in
`CLAUDE.md`): per item een event dumpen (`(Get-WinEvent ...)[0].ToXml()`) of de instelling
opzoeken, en de code + test-fixtures bijstellen waar nodig.

- Registrynamen: `AuditNTLMInDomain`, `16 LDAP Interface Events`, `LdapEnforceChannelBinding`,
  `LDAPServerIntegrity`, `RestrictSendingNTLMTraffic`, `RestrictReceivingNTLMTraffic`,
  `SysvolReady`.
- Engelstalige tool-uitvoer die we parsen: `auditpol.exe` (`Success`/`Failure`/
  `Success and Failure`/`No Auditing`), `setspn.exe -X`. Op een Nederlandstalige Windows-
  installatie kan deze tekst afwijken.
- EventData-veldnamen event 8004 (NTLM/Operational): `UserName`, `Workstation`, `ServerName` —
  matig zeker (8004 is minder uitgebreid publiek gedocumenteerd dan 4624/4776).
- EventData-veldnamen events 2887/2889/3039/3041 (Directory Service, LDAP signing/channel
  binding): `Client`, `IdentityUser`, `Count` — **minst zekere aanname in dit project tot nu
  toe**, eerst valideren. Ook te bevestigen: of 2887/3041 echt periodieke 24-uurs tellingen zijn
  zonder per-client detail (huidige aanname) of toch per-client data bevatten.
