# HardenKit — runbook fase 0-pilot

Stappenplan om HardenKit fase 0 eerst in een lab en daarna bij drie pilotklanten te draaien.
Scope, statussen en succescriteria staan in [`PRD.md`](PRD.md); aannames die nog op een echte
DC geverifieerd moeten worden in [`LESSONS.md`](LESSONS.md) (sectie "pilot-testlijst").

HardenKit zelf is alleen-lezen. Alles in dit runbook dat iets wijzigt (auditbeleid, loggrootte,
geplande taak) doet de engineer bewust en apart.

---

## Deel A — Lab-validatie

Doel: de aannames uit de pilot-testlijst toetsen en de hele keten één keer end-to-end zien
werken vóórdat er een klant-DC aangeraakt wordt.

### A1. Voorbereiding

- Lab met minimaal één DC (Windows Server 2016+) en één member/werkplek om verkeer vanaf te
  genereren. Twee DC's is beter: dan test je ook de DC-compleetheid in het rapport.
- Bij voorkeur ook een Nederlandstalige DC als klanten die hebben (auditpol-uitvoer is
  taalafhankelijk).
- Alleen de map `HardenKit\` is nodig (`Tests\` mag mee, wordt op de DC niet gebruikt). Op de
  werkplek zippen:
  ```powershell
  Compress-Archive -Path D:\git\claudeprojects\hardenkit\HardenKit -DestinationPath $env:USERPROFILE\Desktop\HardenKit.zip -Force
  ```
- Op de DC uitpakken naar `C:\ProgramData\HardenKit\`, zodat het manifest op
  `C:\ProgramData\HardenKit\HardenKit\HardenKit.psd1` staat. Na kopiëren via RDP/download
  eerst de Mark-of-the-Web verwijderen, anders weigert de execution policy de scripts:
  ```powershell
  Get-ChildItem C:\ProgramData\HardenKit -Recurse | Unblock-File
  ```
- Lab/test met internet: kopieer daarnaast `tools\Update-HardenKit.ps1` naar
  `C:\ProgramData\HardenKit\`. Daarmee haal je later een nieuwe versie op zonder opnieuw te
  zippen (zie A7). Niet voor klant-DC's: daar blijft de RMM het kanaal (PRD).
- **Elevated** Windows PowerShell 5.1 openen (geen pwsh 7, de DC-doelgroep is 5.1;
  auditpol en het Security-log vereisen admin):

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force   # ongesigneerd, alleen deze sessie
Import-Module C:\ProgramData\HardenKit\HardenKit\HardenKit.psd1 -Force
Get-Command -Module HardenKit                      # 9 functies verwacht
```

### A2. Nulmeting vóór aanpassingen

```powershell
Test-HKAuditConfig | Select-Object -ExpandProperty Measures | Format-Table
Get-HKBaseline
```

Noteer welke maatregelen `NietVoldaan` of `Onbekend` zijn. Dit is ook meteen de eerste
verificatie van de auditpol-parsing en de registrynamen.

### A3. Auditinstellingen aanzetten

In productie via GPO (zie B3); in het lab mag het lokaal:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# NTLM-audit in domein (= GPO "Restrict NTLM: Audit NTLM authentication in this domain" = Enable all)
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' AuditNTLMInDomain 7 -Type DWord

# LDAP-diagnostiek voor events 2889/3039
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' '16 LDAP Interface Events' 2 -Type DWord

# Security-log vergroten (hier 4 GB)
wevtutil sl Security /ms:4294967296
```

Daarna `Test-HKAuditConfig` opnieuw: alles behalve `ldap_channel_binding` hoort nu `Ok` te zijn.

> **Let op — channel binding.** `Test-HKAuditConfig` verwacht `LdapEnforceChannelBinding = 1`
> en noemt dat "auditstand". Waarde 1 ("when supported") is echter al een vorm van
> afdwingen, geen pure audit. Toets in het lab of dit de juiste voorwaarde is en of event 3039
> ook zonder deze waarde verschijnt. Zet deze waarde **niet** bij een klant zolang dat niet
> uitgezocht is; `ldap_channel_binding` blijft dan `Onbekend` in het rapport.

### A4. Bevindingen bewust uitlokken

| Maatregel | Uitlokken (vanaf de member, tenzij anders vermeld) |
| --- | --- |
| `ntlm_8004` / NTLM naar IP | `net use \\<DC-IP>\c$` |
| `ntlm_4776` | inloggen met een lokaal-vs-domein-account via IP, of `runas /netonly` + IP-share |
| `ntlmv1` | op de member `LmCompatibilityLevel` tijdelijk op 0–2 en een NTLM-verbinding maken |
| `missing_spn` | `klist get http/bestaatniet.<domein>` |
| `duplicate_spn` | `setspn -S http/dubbel.<domein> svc1` en daarna `setspn -A` dezelfde SPN op `svc2` |
| `kerberos_rc4_des` | serviceaccount met `msDS-SupportedEncryptionTypes = 4` (alleen RC4) + SPN, daarna `klist get` op die SPN |
| `ldap_signing` | simple bind op poort 389 met `ldp.exe` (Connect zonder SSL → Bind → Simple bind) |
| `lockouts` | testaccount een paar keer met verkeerd wachtwoord laten inloggen |

Ruim dubbele SPN's, het RC4-account en de LmCompatibilityLevel-wijziging na afloop weer op.

### A5. Eventvelden verifiëren (belangrijkste stap)

Dump per event-ID één echt event en vergelijk de veldnamen met de aannames in `LESSONS.md`:

```powershell
function Show-HKEvent($LogName, $Id) {
    $e = Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $Id } -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($e) { ([xml]$e.ToXml()).Event.EventData.Data | Format-Table Name, '#text' } else { "geen event $Id in $LogName" }
}
Show-HKEvent 'Directory Service' 2889
Show-HKEvent 'Directory Service' 2887
Show-HKEvent 'Directory Service' 3039
Show-HKEvent 'Microsoft-Windows-NTLM/Operational' 8004
Show-HKEvent 'Security' 4768
Show-HKEvent 'Security' 4769
Show-HKEvent 'Security' 4776
Show-HKEvent 'System' 5827
```

Wijkt een veldnaam af: code + testfixtures bijstellen en in `LESSONS.md` het item van de
pilot-testlijst afvinken of corrigeren.

### A6. Hele keten draaien

```powershell
$out = 'C:\ProgramData\HardenKit\Data'
Export-HKData -ClientCode LAB -OutputPath $out
# wat extra verkeer genereren, dan nogmaals — test de incrementele state (*.state.json)
Export-HKData -ClientCode LAB -OutputPath $out
New-HKReport -InputPath $out -OutputPath "$out\LAB.html" -ClientCode LAB -MinimumDays 1
```

Controleer:

- [ ] Rapport opent offline en toont de uitgelokte bevindingen bij de juiste maatregel.
- [ ] Tweede run telt geen events dubbel (vergelijk counts met de eerste run).
- [ ] Bij twee DC's: beide DC's zichtbaar met juiste compleetheid.
- [ ] Rapport **echt bekeken**, niet alleen de tests (zie `LESSONS.md`: zo zijn eerder
      serialisatiebugs gevonden).
- [ ] Geen merkbare CPU/geheugenpiek tijdens `Export-HKData`; duur van een run genoteerd.
- [ ] EDR/AV heeft niet gealarmeerd of geblokkeerd.

### A7. Module bijwerken in het lab

```powershell
C:\ProgramData\HardenKit\Update-HardenKit.ps1              # laatste commit op main
C:\ProgramData\HardenKit\Update-HardenKit.ps1 -Ref 93ab452 # specifieke commit of tag
Import-Module C:\ProgramData\HardenKit\HardenKit\HardenKit.psd1 -Force
```

Het script zet de commit om naar een vaste SHA, downloadt de zip, controleert dat de nieuwe
versie in 5.1 laadt en wisselt dan pas. De vorige versie blijft in `HardenKit.previous\`;
welke commit er staat, lees je in `HardenKit.installed.json`. `Data\` wordt niet aangeraakt.
Terugdraaien: `HardenKit\` verwijderen en `HardenKit.previous\` terug hernoemen, of het script
met de oude SHA als `-Ref` draaien.

**Gate naar Deel B:** alle punten hierboven groen en de pilot-testlijst in `LESSONS.md`
doorgewerkt.

---

## Deel B — Pilot bij klanten

### B1. Vooraf beslissen

Deze open vragen uit de PRD blokkeren de pilot en moeten beantwoord zijn:

- [ ] **Opslaglocatie** JSON/rapporten (lokaal op de DC, klant-share of centraal). Let op: de
      taak draait als SYSTEM, dus bij een share heeft het computeraccount van elke DC
      schrijfrechten nodig.
- [ ] **Codesigning.** Zonder signing draait de pilot met `-ExecutionPolicy Bypass`; bewust
      accepteren of eerst een (intern) certificaat regelen.
- [ ] **Distributie.** De Datto RMM-component bestaat nog niet. Voor de pilot kan handmatig
      (B4); vastleggen wie dat doet.
- [ ] **Bewaartermijn** van de data na de pilot (de JSON is een kaart van zwakke plekken).

### B2. Klanten selecteren en afstemmen

- Drie klanten (succescriteria PRD), bij voorkeur verschillend: één klein/net domein, één
  ouder domein met historie, één met veel member servers/applicaties.
- Per klant afstemmen en vastleggen:
  - [ ] Akkoord van de klant op het meten op de DC's (alleen-lezen, behalve auditbeleid en
        loggrootte).
  - [ ] SOC/EDR-partij geïnformeerd; zo nodig vooraf een uitzondering voor het script/pad.
  - [ ] Lijst van **alle** DC's (inclusief RODC's en DC's op andere sites).
  - [ ] Wie bij de klant het aanspreekpunt is bij vragen of onrust.

### B3. Dag 0 — inrichten

1. Op één DC de nulmeting draaien en bewaren:
   ```powershell
   Test-HKAuditConfig | ConvertTo-Json -Depth 6 | Out-File "<pad>\<klant>_dag0_auditconfig.json"
   ```
2. Auditbeleid via GPO op de OU **Domain Controllers** (bij voorkeur een aparte GPO
   "HardenKit audit", niet de Default Domain Controllers Policy aanpassen):
   - Advanced Audit Policy: Logon, Credential Validation, Kerberos Authentication Service,
     Kerberos Service Ticket Operations — elk succes én fout.
   - Security Options: "Audit: Force audit policy subcategory settings ... to override audit
     policy category settings" = Enabled.
   - Security Options: "Network security: Restrict NTLM: Audit NTLM authentication in this
     domain" = Enable all.
   - Registry (GPP): `NTDS\Diagnostics\16 LDAP Interface Events` = 2.
   - Event Log: Security-log maximale grootte 4 GB (of zoveel dat er ruim meerdere dagen in
     passen, zie stap 4).
3. `gpupdate /force` op de DC's en per DC `Test-HKAuditConfig` controleren.
4. Na een dag op elke DC controleren hoe oud het oudste Security-event is. Dat moet ruim boven
   de 24 uur liggen, zodat een gemiste dagrun niet direct een gat oplevert.

### B4. Dagelijkse verzameling inrichten (per DC)

Zolang er geen Datto-component is, handmatig als geplande taak:

```powershell
$module = 'C:\ProgramData\HardenKit\HardenKit\HardenKit.psd1'
$out    = 'C:\ProgramData\HardenKit\Data'   # of de afgesproken share
$client = 'KLANTCODE'

$cmd = "Import-Module '$module'; Export-HKData -ClientCode '$client' -OutputPath '$out'"
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
           -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"$cmd`""
$trigger = New-ScheduledTaskTrigger -Daily -At 02:30
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2)
Register-ScheduledTask -TaskName 'HardenKit Export' -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings
Start-ScheduledTask -TaskName 'HardenKit Export'   # eerste run direct
```

- Elke DC exact dezelfde moduleversie (`(Get-Module HardenKit).Version`, staat ook in elk
  dagbestand als `moduleVersion`).
- Tijdstip per DC iets spreiden is prima, maar wel dagelijks.

### B5. Tijdens de meetperiode

| Moment | Actie |
| --- | --- |
| Dag 1 | Per DC: dagbestand + `.state.json` aanwezig? Collectors niet op `onbekend`? |
| Wekelijks | Bestanden per DC tellen (gaten = gemiste runs); EDR-meldingen nagaan |
| Dag 7 | Tussenrapport met `-MinimumDays 7`, samen met een engineer doorlopen: kloppen de bevindingen, zitten er rare waarden in? |
| Dag 28+ | Meetperiode klaar, bij voorkeur over een maandafsluiting heen |

```powershell
New-HKReport -InputPath <map met alle dagbestanden van alle DC's> `
             -OutputPath <klant>_HardenKit_<yyyyMMdd>.html -ClientCode <klant>
```

Bij een share per DC: eerst alle dagbestanden van alle DC's naar één map verzamelen.

### B6. Afronding per klant

1. Eindrapport (`-MinimumDays 28`, de default) doorlopen met een engineer die het rapport
   nog niet kent. Lukt dat zonder uitleg? Dat is een van de succescriteria.
2. Per bevinding: bekend of nieuw? Vastleggen.
3. Minimaal één maatregel met status Groen kiezen en doorvoeren, eerst in auditstand of
   gefaseerd, met een terugdraaiplan.
4. Een week na doorvoeren: storingen? Een nieuwe `Export-HKData`-run laat zien of er alsnog
   gebruik opduikt.
5. Geplande taak verwijderen of laten doorlopen (afspraak met klant), en data volgens de
   afgesproken bewaartermijn opruimen.

### B7. Evaluatie (gate fase 0 → fase 1)

Per klant invullen:

| Criterium (PRD) | Klant 1 | Klant 2 | Klant 3 |
| --- | --- | --- | --- |
| Minimaal één nog onbekende bevinding | | | |
| Minimaal één maatregel doorgevoerd zonder storing | | | |
| Geen merkbare DC-belasting en geen EDR-incidenten | | | |
| Rapport bruikbaar zonder uitleg van de bouwer | | | |

Alle criteria bij alle drie de klanten gehaald: fase 0 geslaagd, fase 1 kan starten.
Bevindingen over de tool zelf (verkeerde veldnamen, valse positieven, onduidelijke teksten)
gaan naar `LESSONS.md` en worden vóór fase 1 opgelost.
