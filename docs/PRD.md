# PRD HardenKit

Oct 1, 2026 · @Stefan

## Samenvatting

HardenKit is een alleen-lezen PowerShell-module die meet wat er breekt als we on-premises Active Directory hardenen, zodat we maatregelen veilig kunnen doorvoeren. Bestaande tools (PingCastle, Purple Knight) vertellen wát er mis is; HardenKit vertelt per maatregel wie of wat er nog gebruik van maakt.

De module verzamelt vier weken lang gegevens uit eventlogs en configuratie op de domain controllers, schrijft die als JSON weg en maakt er een zelfstandig HTML-rapport van met een stoplicht per maatregel. Fase 0 meet alleen op DC's; later komen member servers, serviceaccounts en een Rewst-koppeling erbij.

## Probleemstelling en doelen

Hardeningadviezen blijven liggen omdat niemand weet wat er omvalt. Technici durven NTLMv1, SMBv1 of RC4 niet uit te zetten zonder te weten welke printer, applicatie of serviceaccount ervan afhangt. Daardoor blijven klantdomeinen onveilig, en vaak ook trager door NTLM-fallback, lockout-stormen en clients die zich bij de verkeerde DC aanmelden.

Doelen:

- Per maatregel een onderbouwde go/no-go op basis van minimaal vier weken meetdata.
- Per no-go een lijst van de concrete apparaten, accounts en servers die eerst opgelost moeten worden.
- Problemen zichtbaar maken die nu al stuk zijn maar niet opvallen (Netlogon-weigeringen, zwakke certificaatmapping, ontbrekende SPN's).
- Veiligheid en performance samen verbeteren door gedeelde oorzaken aan te pakken.
- Herhaalbaar uitvoerbaar over alle klanten van de MSP, via de bestaande RMM.

## Uitgangspunten

1. **Geen bevinding zonder actie.** Elke bevinding heeft een concreet risico of performance-effect, noemt de betrokken objecten en eindigt in een uitvoerbare actie. Geen scores zonder vervolg.
2. **Alleen lezen.** De module wijzigt niets aan het domein. Uitzondering: het aanzetten van auditinstellingen, en dat gebeurt bewust via een aparte, gemelde GPO-wijziging.
3. **Meten waar meten nodig is.** We bouwen PingCastle of Purple Knight niet na. HardenKit richt zich op gedrag dat je alleen ziet door te meten, en op de vraag of een fix veilig is.
4. **Onbekend is niet groen.** Als een benodigde auditinstelling of logbron ontbreekt, toont het rapport "onbekend", nooit "veilig".
5. **Geen afhankelijkheid van internet op de DC.** HardenKit kan adviseren om internettoegang van DC's dicht te zetten, dus de eigen werking mag daar niet van afhangen.
6. **Transparant naar de klant.** Wat we verzamelen, waarom en waar het staat, is vooraf vastgelegd en controleerbaar.

## Doelgroep en gebruikers

| Gebruiker | Wat ze met HardenKit doen |
| --- | --- |
| Systeembeheerder / engineer MSP | Rolt de meting uit, leest het rapport, lost blokkerende bevindingen op en voert maatregelen door |
| Security lead / architect MSP | Bepaalt welke maatregelen per klant aan de beurt zijn en bewaakt de voortgang over klanten heen |
| Accountmanager / service delivery | Gebruikt het rapport in gesprekken met de klant en voor NIS2-gerelateerde vragen |
| Klant (IT-contact of directie) | Ontvangt het rapport als onderbouwing van geplande wijzigingen |

De eerste versie is voor intern gebruik binnen de MSP. Aanbieden aan andere MSP's is een latere keuze (zie open vragen).

## Scope en fasering

Fase 0 meet alleen op de DC's en levert al de go/no-go per maatregel; latere fasen voegen detail en automatisering toe.

Fase 0 heeft geen member servers, Rewst of centrale opslag nodig. Elke volgende fase start pas als de gate daarvoor gehaald is.

### Buiten scope

- Wijzigingen doorvoeren door de module zelf; HardenKit blijft alleen-lezen.
- Hardening van Entra ID en Microsoft 365.
- Breed meten op alle werkplekken; alleen gericht in fase 2.
- Een eigen webapp of centrale opslag; mogelijk later.
- Het nabouwen van configuratiescans die PingCastle, Purple Knight of ADCS-tools al doen.

## Functionele eisen

### Nulmeting (configuratie, per DC)

De nulmeting legt vast hoe het domein er vóór de meting voor staat en of de meting betrouwbaar kan zijn.

- OS-versie, rol (PDC-emulator e.d.) en lijst van alle DC's in het domein.
- Auditinstellingen (`auditpol /get /category:*`) en of succes én fout worden gelogd waar nodig.
- Maximale grootte van de Security-log en datum van het oudste event.
- LDAP-diagnostiekniveau, LDAP signing- en channel binding-instellingen.
- LmCompatibilityLevel, NTLM-beperkingen, SMB1-status, Print Spooler-status.
- Dubbele SPN's (`setspn -X`).
- Tijdbron van de PDC-emulator.
- SYSVOL-replicatie (FRS of DFSR) en replicatiestatus.
- Leeftijd krbtgt-wachtwoord.

### Metingen uit eventlogs

| Maatregel / thema | Log | Event-ID's | Voorwaarde | Wat we zien | Fase |
| --- | --- | --- | --- | --- | --- |
| NTLMv1 / LM | Security | 4624 (LmPackageName) | Logon-auditing | Account, werkstation en IP met NTLMv1 | 0 |
| NTLM algemeen | NTLM/Operational | 8004 | NTLM-audit in domein aan | Client, account en doelserver met NTLM | 0 |
| NTLM algemeen | Security | 4776 | Audit Credential Validation | NTLM-credentialvalidaties | 0 |
| LDAP signing | Directory Service | 2887, 2889 | 2889 vereist verhoogde LDAP-diagnostiek | IP en account met unsigned of simple bind | 0 |
| LDAP channel binding | Directory Service | 3039–3041 | Channel binding in auditstand | Clients zonder channel binding | 0 |
| Kerberos RC4 / DES | Security | 4768, 4769 (type 0x17, 0x18, 0x1, 0x3) | Kerberos-auditing | Accounts en services met RC4 of DES | 0 |
| Ontbrekende SPN (fallback) | Security | 4769 met fout 0x7 | Foutauditing Service Ticket Operations | Gevraagde servicenaam die niet bestaat | 0 |
| Dubbele SPN | System | 11 (KDC) | Geen | SPN gekoppeld aan meerdere accounts | 0 |
| Netlogon secure channel | System | 5827, 5828 | Geen | Apparaten die al geweigerd worden | 0 |
| Certificaatmapping | System | 39, 40, 41 (Kdcsvc) | Geen | Zwakke certificaatkoppelingen | 0 |
| Netlogon-verzadiging | System | 5816–5819 | Geen | Time-outs door NTLM-belasting | 0 |
| Lockouts / mislukte logons | Security | 4740, 4625 | Logon-auditing | Bron van lockouts en foute wachtwoorden | 0 |
| Onbekende subnetten | System / netlogon.log | 5807, NO_CLIENT_SITE | Geen | Clients zonder AD-site | 0 |
| Tijdsynchronisatie | System | W32Time-events | Geen | Tijdsafwijking en foute tijdbron | 0 |
| Replicatie | Directory Service / DFSR | o.a. 1311, 1865, 2042 | Geen | Replicatiefouten | 0 |
| Zware LDAP-queries | Directory Service | 1644 | Field Engineering-diagnostiek | Applicaties met dure queries | 1 |
| Uitgaand verkeer DC | Momentopnames + DNS-cache | optioneel 5156 / Sysmon 3 | 5156 alleen tijdelijk | Proces en bestemming per uitgaande verbinding | 0 |
| SMBv1 | SMBServer/Audit | 3000 | `AuditSmb1Access` aan | Clients die SMBv1 gebruiken | 1 (alle servers) |
| Inkomend NTLM / lokale accounts | NTLM/Operational | 8003 | NTLM-audit lokaal | NTLM met lokale accounts | 1 |
| Herkomst NTLM (proces) | NTLM/Operational (client) | 8001 | NTLM-audit lokaal | Welk proces NTLM start | 2 (gericht) |
| Kerberos-fouten client | System (client) | 4 (Kerberos) | Geen | SPN aan verkeerd account | 2 (gericht) |

Open punt: Microsoft fasert RC4 voor Kerberos uit en heeft daarvoor extra auditevents toegevoegd. In fase 0 uitzoeken welke dat zijn en of ze 4768/4769 kunnen vervangen.

### Inventaris (fase 1)

Via dezelfde module op member servers: scheduled tasks, services, IIS-pools en SQL Agent-jobs met hun uitvoerende account, gekoppeld aan AD-gegevens van serviceaccounts (leeftijd wachtwoord, SPN's, preauthenticatie, delegatie). Doel: zien wat er breekt bij het resetten of uitschakelen van een account.

## Correlatie en beoordeling

Elke maatregel krijgt na de meetperiode één status, met de betrokken objecten erbij.

| Status | Betekenis | Voorwaarde |
| --- | --- | --- |
| Groen | Kan dicht | Minimaal 28 dagen gemeten, auditinstellingen in orde, geen gebruik gezien |
| Oranje | Kan dicht na fixes | Gebruik gezien, maar alle bronnen zijn bekend en oplosbaar (bijv. ontbrekende SPN) |
| Rood | Breekt nu | Gebruik door bronnen die niet zonder meer op te lossen zijn (oude apparatuur, leverancier) |
| Onbekend | Niet te beoordelen | Auditinstelling ontbreekt, log te kort of meetperiode niet compleet |
| Al stuk | Probleem bestaat nu al | Weigeringen gezien (Netlogon, certificaatmapping, replicatie) |

Correlatieregels in fase 0, allemaal met alleen DC-data:

- **NTLM-fallback door ontbrekende SPN:** dezelfde client krijgt 4769 met fout 0x7 voor service X en authenticeert kort daarna via NTLM (8004) naar dezelfde server. Conclusie: oranje, fix = SPN registreren.
- **NTLM naar IP of alias:** 8004 met een IP-adres of DNS-alias als doel. Conclusie: oranje, fix = verbinden op servernaam of SPN voor de alias.
- **Eén oorzaak, meerdere effecten:** NTLM-volume dat samenvalt met Netlogon-verzadiging (5816–5819), of tijdsafwijking die samenvalt met Kerberos-fouten, wordt als één bevinding getoond.
- **Drempels:** losse 0x7-fouten zonder bijbehorend NTLM-verkeer tellen we wel, maar markeren we pas boven een instelbare drempel.

De meetperiode is standaard 28 dagen en instelbaar. Het rapport toont per maatregel de werkelijke gemeten periode.

## Architectuur

HardenKit is één PowerShell-module met gescheiden verzamel- en rapportagestappen; de DC praat alleen met de RMM-agent.

Verzamelen gebeurt dagelijks op elke DC; het rapport wordt achteraf gemaakt uit alle JSON-bestanden van een klant.

### Modulefuncties

| Functie | Doel | Fase |
| --- | --- | --- |
| `Test-HKAuditConfig` | Controleert of benodigde audit- en loginstellingen aanstaan; bepaalt waar "onbekend" geldt | 0 |
| `Get-HKBaseline` | Nulmeting van configuratie, SPN's, tijdbron, replicatie | 0 |
| `Get-HKNtlmUsage` | NTLMv1, NTLM-gebruik, NTLM naar IP of alias | 0 |
| `Get-HKLdapBinding` | Unsigned binds en channel binding | 0 |
| `Get-HKKerberos` | RC4/DES, fout 0x7, dubbele SPN's, certificaatmapping | 0 |
| `Get-HKDomainHealth` | Netlogon, lockouts, subnetten, tijd, replicatie | 0 |
| `Get-HKOutbound` | Momentopnames uitgaande verbindingen met proces en DNS-naam | 0 |
| `Export-HKData` | Roept collectors aan, aggregeert en schrijft JSON per DC per dag | 0 |
| `New-HKReport` | Leest een map met JSON, correleert en schrijft één HTML-rapport | 0 |
| `Get-HKServiceInventory` | Taken, services, IIS-pools en SQL-jobs met hun account | 1 |

De module herkent zelf of hij op een DC of member server draait en kiest daarop welke collectors draaien.

### Dataformaat

- Eén JSON-bestand per host per dag, plus een statusbestand met de laatst gelezen RecordId per log.
- Elke regel is een aggregaat: maatregel, client (FQDN en IP), account (naam en SID), doel, aantal, eerste en laatste keer gezien (UTC).
- Kopgegevens per bestand: schemaversie, klantcode, hostnaam, rol, moduleversie, meetvenster en status per collector (ok, onbekend, fout).
- Het schema wordt vastgelegd en geversioneerd, zodat een latere API of Rewst-workflow hetzelfde formaat kan lezen.

```json
{
  "schema": "1.0",
  "client": "KLANT01",
  "host": "dc01.klant.local",
  "role": "DC",
  "window": { "from": "2026-10-01T00:00:00Z", "to": "2026-10-02T00:00:00Z" },
  "collectors": { "ntlm": "ok", "ldap": "onbekend" },
  "findings": [
    {
      "measure": "ntlmv1",
      "client": { "fqdn": "scanner01.klant.local", "ip": "10.0.0.50" },
      "account": { "name": "svc_scan", "sid": "S-1-5-21-..." },
      "count": 412,
      "firstSeen": "2026-10-01T06:02:11Z",
      "lastSeen": "2026-10-01T22:47:03Z"
    }
  ]
}
```

## Distributie, installatie en updates

GitHub is de bron en het bouwpunt; de RMM is het standaard installatiekanaal. De DC hoeft daardoor niet naar internet.

- **Releases:** elke release heeft een vast versienummer en is gesigned met het codesigning-certificaat van de MSP, zodat de module werkt onder executionpolicy AllSigned en de EDR op handtekening kan vertrouwen.
- **Standaardroute:** de RMM haalt de release op, controleert hash en handtekening en plaatst de module in de module-map van de DC.
- **Alternatief:** een interne share als PowerShell-repository, waar `Install-Module` naar wijst. Voor klanten zonder onze RMM.
- **Gemaksroute:** direct vanaf GitHub installeren op de server is toegestaan voor een eerste meting, maar verdwijnt zodra de klant gehardend is. GitHub komt niet in de allowlist die HardenKit zelf voorstelt.
- **Versiebeheer:** versies worden gepind en pas uitgerold na eigen test. Geen automatische "latest" op DC's.
- **Repository-beveiliging:** verplichte 2FA, branch protection, verplichte review bij merges. Het signing-certificaat staat niet in GitHub en wordt apart beheerd.
- **Geen** `irm | iex`-patroon: dat lijkt op een aanval en wordt terecht door EDR's tegengehouden.

## Rapportage en integraties

### HTML-rapport

`New-HKReport` maakt per klant één zelfstandig HTML-bestand: data als JSON in de pagina, geen externe scripts of fonts, werkt offline.

- Overzicht: stoplicht per maatregel, gemeten periode, aantal DC's met complete data.
- Per maatregel: betrokken clients, accounts en servers met aantallen, eerste en laatste keer gezien, en de voorgestelde actie.
- Aparte sectie "al stuk" voor bevindingen die nu al weigeringen veroorzaken.
- Allowlist-voorstel voor uitgaand verkeer van DC's, per proces.
- Geschikt om met de klant te delen; technische details inklapbaar.

### Rewst (fase 2)

Rewst orkestreert en verbindt; HardenKit blijft de meter.

- Rewst start de meting via de RMM-integratie en haalt de uitvoer via de RMM terug. De DC post niet zelf naar een webhook.
- Rewst ontvangt een compacte samenvatting per run, niet de volledige dataset.
- Uitkomsten naar IT Glue als flexible asset met de hardeningstatus per klant.
- Concrete bevindingen als tickets in de PSA, zodat ze in de normale werkstroom komen.
- Als toch een webhook wordt gebruikt: URL als geheim behandelen, authenticatie waar mogelijk, en de inhoud valideren tegen het JSON-schema.
- Eventuele daadwerkelijke hardening via aparte Rewst-workflows met goedkeuringsstap, los van HardenKit.

## Beveiliging, privacy en transparantie

De verzamelde data is een kaart van zwakke plekken in een klantdomein en moet ook zo behandeld worden.

- **Dataminimalisatie:** geen wachtwoorden, hashes of secrets. Bij scripts met mogelijke wachtwoorden alleen de vindplaats (bestand, regel).
- **Aggregatie op de DC:** per maatregel, client en account een telling met eerste en laatste keer gezien; geen ruwe events.
- **Opslag:** JSON en rapport bij de klant (share) of op een versleutelde beheermachine; verwijderen na afronding van de analyse, tenzij afgesproken.
- **AVG:** accountnamen en IP-adressen zijn persoonsgegevens. Verzameling, doel en bewaartermijn opnemen in de verwerkersovereenkomst en dienstbeschrijving.
- **EDR:** module gesigned en gestart via de RMM; uitzondering in de EDR op handtekening en pad, nooit een brede uitzondering op PowerShell.
- **Wijzigingen:** het aanzetten van auditinstellingen en het vergroten van eventlogs gaat via een gemelde change bij de klant.
- **Transparantie:** documentatie van wat HardenKit leest is voor de klant beschikbaar; bij een publieke repository is ook de code controleerbaar.
- **Toekomstige centrale opslag:** per klant gescheiden, per klant eigen authenticatie, EU-regio, endpoint accepteert alleen data en stuurt nooit opdrachten terug.

## Niet-functionele eisen

| Eis | Invulling |
| --- | --- |
| Compatibiliteit | Windows PowerShell 5.1; Windows Server 2016 en nieuwer als doel, oudere DC's waar mogelijk met beperkte functies |
| Belasting DC | Eventqueries met XPath-filters (`Get-WinEvent`), incrementeel lezen vanaf laatste RecordId per log; een dagelijkse run mag de DC niet merkbaar belasten |
| Betrouwbaarheid | Gedeeltelijke uitval (log niet leesbaar, rechten ontbreken) leidt tot "onbekend" voor die maatregel, niet tot een afgebroken run |
| Rechten | Minimaal benodigde rechten; standaard uitgevoerd als SYSTEM via de RMM op de DC |
| Datavolume | JSON per DC per dag compact houden door aggregatie |
| Correleerbaarheid | Vaste sleutels in alle data: FQDN, account met SID, tijd in UTC, schemaversie |
| Draagbaarheid | Geen afhankelijkheden buiten standaard Windows-componenten en de module zelf |

## Risico's en open vragen

### Risico's

| Risico | Gevolg | Maatregel |
| --- | --- | --- |
| Security-log rolt te snel over | Gebruik gemist, onterecht groen | Logs vergroten, dagelijks incrementeel verzamelen, status "onbekend" bij gaten |
| Meetperiode te kort | Maandelijkse of kwartaalprocessen gemist | Minimaal 28 dagen, bij voorkeur over een maandafsluiting heen |
| EDR blokkeert of alarmeert | Meting faalt, onrust bij klant of SOC | Signing, start via RMM, vooraf afgestemde uitzondering |
| Gecompromitteerde repository | Kwaadaardige code op DC's van alle klanten | 2FA, branch protection, reviews, signing buiten GitHub, gepinde versies |
| Gevoelige data lekt | Aanvaller krijgt kaart van zwakke plekken | Dataminimalisatie, versleutelde opslag, bewaartermijn |
| Niet alle DC's gemeten | Onvolledig beeld | Rapport toont per DC of data compleet is |
| Valse zekerheid bij groen | Toch storing na doorvoeren | Groen alleen bij complete meting; maatregelen eerst in auditstand of gefaseerd doorvoeren |

### Open vragen

- [ ] Welke extra RC4-auditevents heeft Microsoft toegevoegd, en vervangen die 4768/4769?
- [ ] Kan Rewst via onze RMM-integratie scripts starten en de uitvoer ophalen?
- [ ] Ondersteunt Rewst authenticatie op webhooks?
- [ ] Publieke of privérepository?
- [ ] Blijft HardenKit intern, of bieden we het later aan andere MSP's aan? Zo ja: merkcheck en domeinnamen.
- [ ] Welke drempelwaarden gebruiken we voor 0x7-fouten en lockouts?
- [ ] Waar bewaren we JSON en rapporten: share bij de klant of centraal?
- [ ] Welk codesigning-certificaat gebruiken we en wie beheert het?

## Succescriteria

Fase 0 is geslaagd als de pilot bij drie klanten het volgende oplevert:

- Bij elke pilotklant minimaal één bevinding die nog niet bekend was (bijv. NTLMv1-apparaat, ontbrekende SPN, Netlogon-weigering).
- Minimaal één hardeningmaatregel per klant doorgevoerd op basis van het rapport, zonder storing.
- Geen merkbare belasting op de DC's en geen EDR-incidenten door de module.
- Engineers kunnen het rapport lezen en er acties uit halen zonder uitleg van de bouwer.

Op langere termijn meten we: aantal doorgevoerde maatregelen per klant, daling van NTLM-volume, minder lockouts en Netlogon-time-outs, en de tijd tussen bevinding en oplossing.
