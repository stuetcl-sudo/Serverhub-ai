# Oprindelig leveringsrapport — ServerHub AI OS

Denne rapport beskriver den første leverance. Den efterfølgende stabilitets-/autonomiopdatering og dens aktuelle verifikationsstatus er dokumenteret i [overhaul-report.md](overhaul-report.md), [installation.md](installation.md) og [upgrade.md](upgrade.md).

**Dato: 22. oktober 2026 · Softwareversion 1.0.0 · Status: implementeret og testet kildekodeleverance; ikke erklæret produktionsklar.**

Der er bygget fungerende software og en native installationspakke. Den fulde vision om en selvstændig administrator, der kan løse alle de beskrevne opgaver, er endnu ikke færdig. Nedenfor skelnes mellem implementeret kode, faktisk verificerede forløb og manglende funktioner. Ingen eksisterende produktionsserver, firewall, SSH, VPN, Docker-workload, database eller integration blev ændret.

## 1. Repository og leverance

Leverancen er `serverhub-ai-os.zip`, med repository, meningsfuld Git-historik, Python-kildekode og wheel, React/TypeScript-kildekode og bygget frontend, låste/hashkontrollerede afhængigheder, migrationer, native scripts/systemd-definitioner, automatiske tests, CI og dokumentation.

Kildekode og commit-forløb offentliggøres i [stuetcl-sudo/Serverhub-ai](https://github.com/stuetcl-sudo/Serverhub-ai). GitHub-importen bevarer filindhold og rækkefølgen af de meningsfulde commits; GitHub tildeler nye commit-identiteter ved API-import. Det oprindelige arkiv indeholder den lokale Git-historik samt byggede artefakter. Ved kloning fra GitHub skal artefakter bygges som beskrevet i installationsguiden. Ingen produktionsdata, API-nøgler eller private signeringsnøgler indgår.

## 2. Installation

Start i en **disponibel Ubuntu Server 24.04 x86_64 VM**. Arkivet indeholder det færdige wheel og `frontend/dist`, så Node ikke behøves for at køre produktionsinstallationen.

```sh
cd serverhub-ai-os
./scripts/install.sh --check
./scripts/install.sh --stage --root /tmp/serverhub-install-check \
  --public-url https://serverhub.example.net
```

Først efter VM-gennemgangen:

```sh
sudo ./scripts/install.sh --apply --install-dependencies \
  --public-url https://serverhub.example.net --owner dennis
```

Se `installation.md` for HTTPS, initial bruger, PostgreSQL-identiteter, agenttilmelding og aktivering. Installationsstaging er verificeret; faktisk OS-installation med systemd og forskellige Linux-brugere er ikke verificeret i dette miljø.

## 3. Implementeret funktionalitet

| Område | Implementeret leverance |
| --- | --- |
| Native platform | FastAPI, PostgreSQL, Alembic, CLI og systemd-pakker. Docker kræves ikke for controlleren. |
| Rettigheder | Argon2-passwords, opake hash-lagrede sessions, roller, kapabiliteter, værts-/projektgrænser, udløb og produktionsflag. Rettigheder kontrolleres ved indsendelse, udførelse og agentlevering. |
| Vedvarende jobs | PostgreSQL-kø, parent/dependencies, checkpoints, deadlines, retries, global/værtsvis samtidighed, pause/cancel, restart recovery, logs og budgetter. |
| Planlægning | Vedvarende intervalplaner; mistede perioder samles, ufærdige jobs overlapper ikke og tilladelser fornys aldrig automatisk. Owner-API; endnu ingen dedikeret planlægningsside. |
| Linux-agenter | Individuelle identiteter, engangstilmelding, HTTPS-validering, tilbagekaldelse, offline-markering, lokal SQLite-kommandejournal og beskyttelse mod gentagne tvetydige ændringer. |
| Inventory | OS/kernel/pakker/hardware/ressourcer/netværk/DNS/porte/systemd og brokerbaseret Docker/firewall/scannere. Manglende adgang registreres eksplicit. |
| Vidensgraf og historik | Verificerede observationer og afledte relationer markeres forskelligt; metrics, hændelser, findings og struktureret operationel hukommelse gemmes. |
| AI-framework | OpenAI-kompatibel API og Ollama, modelruter, strukturerede værktøjer, otte specialistkonfigurationer, vedvarende tool-loop, retries og token-/prisbudget. |
| Kontrollerede handlinger | Fast allowlist, separat privilegeret broker, tilladte systemd-/container-restarts, registrerede/pinnede Compose-projekter, faste netværksprober og scannerkommandoer. |
| Diagnose/selvheling | Hændelser fra ressourcegrænser/baselines, fejlede services og usunde containere. Konfigurerede monitoring-jobs kan vælge tilladte restarts og kontrollere ny inventory bagefter. |
| Integrationer | Home Assistant, AdGuard Home, UniFi Network, UISP, Prometheus, Grafana, PostgreSQL, GitHub og eksisterende MCP-metadata via dokumenterede/faste adapters. Se separat verifikationsstatus nedenfor. |
| Udvikling | Konfigurerede Git-workspaces/branches, validerede patches, sandbox-runner, projektkommandoer, uafhængige checks og deterministiske kandidatarkiver. |
| Webinterface | Mørkt responsivt dashboard med ægte API-data, hosts/topologi/Docker/netværk/porte/security/chat/jobs/policies/metrics/incidents/memory/backups/models/users/audit/integrationer/projekter. |
| MCP/OAuth | Afgrænsede tools, præregistrerede klienter, S256 PKCE, audience/scopes, engangskoder, roterende refresh-tokens, replay-tilbagekaldelse og begrænsede policy-skabeloner. |
| Backup/recovery | Rigtig pg_dump, checksums, konfigurationsarkiv, restore-drill til ny disponibel database, beskyttede destinationsmapper, uafhængig stabil recovery-runtime. |
| Opdatering | Ed25519-signaturer, artefakthashes, faktisk wheel-kodekontrol mod beskyttet anchor, afvisning af ændrede entry points/startup-payloads, staging og uafhængig rollback for kompatible schemaer. |

Et job med status `succeeded` betyder, at den implementerede jobprocedure blev færdig. En AI-opsummering er **ikke** automatisk verificeret bevis for, at hele brugerens ønskede resultat er opnået; AI-resultater og hukommelse markerer dette eksplicit.

## 4. Automatiske testresultater

| Kontrol | Faktisk resultat |
| --- | --- |
| Samlet Python-suite med rigtig PostgreSQL | **111 bestået, 0 fejl, 0 sprunget over**. |
| React/REST-tests | **20 bestået, 0 fejl**. |
| Frontend-build | Vite 7.3.7/TypeScript gennemført; 274 KB JS før gzip. |
| Python wheel og sdist | Bygget. Wheel installeret i separat, ren runtime med hashkontrolleret dependency-lock. |
| Installeret wheel | Migrationer og `/health` gennemført med udviklingsdatabase. |
| Faktisk PostgreSQL 16.2 | Migrationer, separat workerproces, claim-samtidighed, restart-checkpoints og hård deadline verificeret. |
| Databasegrænser | Worker fik afvist policy-/emergency-/audit-/backupændringer, OAuth/session/enrollment-læsning og ændring af planernes indhold. |
| Rigtig databasebackup | pg_dump-arkiv, checksum, pg_restore og restore-drill til separat genereret database gennemført. |
| OAuth/MCP | Code replay, refresh replay, scopes, audience, klient-/redirect-/resourcekontrol, Origin og tool-argumenter testet. |
| Installer staging | Konfiguration, rettigheder, systemd-filer og recovery-grænser kontrolleret i separat filsystemtræ. |
| Rigtig release-staging | Faktisk wheel/signatur/kode-anchor kontrolleret; en separat native release-runtime med dependencies, webassets og migrationer blev opbygget i isoleret filsystem. Ingen aktivering af rigtige systemd-services. |
| Release/rollback | Signatur, ændrede artefakter, falsk uændret trust-digest, ændret policy-kode, `.pth`-payloads, arkivgrænser og faktisk beskyttet filrollback testet. |
| Kørende samlet system | Native API + rigtig PostgreSQL + separat worker + agentbibliotek gennemførte et persistent workflow med to friske inventory-kommandoer og gyldig auditkæde. |
| Browser | Rigtigt login, live host og jobresultat gennemført i Chromium; 390 px-layout uden vandret dokument-overflow; ingen JavaScript-fejl. Desktop visuelt inspiceret. |
| Ruff | Bestået. |
| Python dependency-audit | Ingen kendte sårbarheder fundet i det leverede runtime-lock efter opdatering af cryptography til 50.0.2. |
| npm-audit | 0 kendte sårbarheder efter opdatering af Vite/Vitest. |

Testresultater og maskinlæsbare rapporter findes i `docs/verification/`. Python-testværktøjet udsendte én Starlette/httpx-deprecation-advarsel; testene bestod. Testene er ikke en garanti mod alle fejl eller sårbarheder.

## 5. Verificerede integrationer

| Integration | Verifikationsniveau |
| --- | --- |
| Linux | Rigtig lokal discovery: 696 installerede pakker samt OS/hardware/RAM/diske/listeners. Netlink/systemd/neighbor-indsamling var begrænset af testmiljøet og blev rapporteret som mangler. |
| PostgreSQL | Rigtig database, schema, kø, flere processer, grants, audit-trigger, dump og restore. |
| HTTP-agent/controller | Rigtigt lokalnetværksforløb på loopback i disponibelt miljø. TLS-krav/afvisninger er testet; rigtig remote TLS-installation og særskilte OS-brugere er ikke prøvet. |
| Home Assistant | API-kontrakttests med simuleret HTTP: læsning, allowlistet power-ændring, checkpoint og readback. Ingen rigtig HA-instans kontaktet. |
| AdGuard Home | Kontrakttests: refresh/regler/udskiftning, DNS-canaries og rollback, også ved timeout efter tvetydig filtertilføjelse. Ingen rigtig AdGuard-instans kontaktet. |
| UniFi/UISP/Prometheus/Grafana/GitHub/legacy MCP | Implementerede adaptere og udvalgte HTTP-kontrakttests; ingen live enheder/konti. UniFi/UISP-håndtering er begrænset inventory, ikke generel enhedsadministration. |
| OpenAI-kompatibel/Ollama | Simulerede providerforløb med tools, fejl, retries og budgetter. Ingen betalt model eller lokal Ollama-model blev brugt til et rigtigt driftsproblem. |
| Git | Rigtige disponible repositories, branch, patchvalidering og kandidatarkiv. |
| Docker/systemd/Trivy/Lynis | Kontrollerede adaptere og negative/registrerede target-tests. Ingen rigtig Dockerdaemon, systemd-serviceændring eller live scannerinstallation blev gennemført. |
| ChatGPT | Lokal MCP/OAuth testet. En rigtig forbindelse fra brugerens ChatGPT-konto er ikke afprøvet. |

## 6. Funktioner, der ikke er fuldt implementeret

- Ingen generel autonom lukning af porte, firewall-/SSH-/VPN-/routingændringer eller fjernelse af ukendte services. Der findes ingen ubeskyttet kommandobagvej.
- Ingen universel diagnose/optimering af Home Assistant, netværket eller alle Docker-workloads. De implementerede prober og reparationsprocedurer har et konkret begrænset scope.
- Ingen dynamisk research og tillidsvurdering af helt nye AdGuard-filterkilder. Udskiftning bruger kilder, ejeren allerede har registreret.
- Applikationskataloget vælger/forklarer og laver planer. Helt automatisk PDF-installation, secrets/dependencies, reverse-proxy-registrering, backupregistrering og rollout af en ny app er ikke en færdig samlet funktion. Brokerdeployment kræver registrerede immutable projekter.
- Udviklingsagenten har endnu ikke en komplet automatisk test→patch→test-fejlretningssløjfe, en vedvarende kørende stagingserver eller generisk produktionsdeployment. Jarvis OS er ikke blevet færdigudviklet eller ændret under denne opgave.
- Specialisterne er otte model-/instruktionskonfigurationer med fælles vedvarende state, ikke otte samtidigt kørende og uafhængigt verificerende driftsagenter.
- Hukommelsen er struktureret lagring/søgning og målte baselines; ikke model-finetuning eller en garanti for korrekt rodårsagsanalyse.
- Selvforbedringer kan foreslås/udvikles som kandidater. Ændring af Python-kode kræver særskilt offline ejerreview, fordi hele pakken er anchored. En fuldt autonom godkendelses-/signeringsservice til egen kode er ikke implementeret.
- Model-/integrationskonfiguration vises i UI, men opdateres som beskyttede native filer. Der er endnu ingen MFA/OIDC/SSO, TOTP, WebAuthn, CIMD eller offentlig OAuth-DCR.
- Ingen fuld ændringshistorik for alle eksterne konfigurationer, komplet netværksasset-attribution eller aktiv ekstern internet-eksponeringsscanner. Wildcard-bind adresser behandles ikke som verificeret internetadgang.
- Ingen generel eksport/notifikationsplatform, automatisk offsitebackup, retention/pruning, HA-controller/failover eller fuld stor-skala belastningstest.

## 7. Kendte begrænsninger og sikkerhed

Det begrænsede buildmiljø havde systemd uden fungerende PID1, kun UID 0 i bruger-namespace og ingen tilladte Unix-sockets. PostgreSQL blev kørt som disponibel testproces med en test-only UID-tilpasning på `initdb/postgres`; denne tilpasning findes **ikke** i produktkoden, wheel, CI eller arkivet. Produktionsinstallationen bruger almindelige separate Linux-/PostgreSQL-brugere.

Faktisk Ubuntu-VM-installation, systemd-sandboxing, brokerpeer-identitet mellem forskellige brugere, ARM64/Pi, remote certifikater og root-serviceadfærd mangler derfor en rigtig OS-generalprøve. Bubblewrap-runneren fejler lukket her, fordi nye namespaces ikke er tilladt; udførelse af projektkommandoer i denne sandbox er ikke end-to-end verificeret.

Root og databaseadministrator er fortsat trust anchors. API-processen har ejerstyret policy-administration og er derfor en del af den betroede kontrolflade. Beskyt den med TLS og begrænset netadgang. Redaction genkender almindelige secrets, men kan ikke garantere, at vilkårlig applikationstekst aldrig indeholder en hemmelighed.

Et emergency stop kan stoppe yderligere jobclaims og kommandoer, men kan ikke tilbagekalde en ekstern sideeffekt, der allerede er startet. Tvetydige ændringer kræver kontrol af checkpoint/journal. Release-rollback skifter kode for samme schema; den ruller ikke databasedata eller vilkårlige migrationer tilbage. Backupdestinationens rettigheder beskytter mod agenten, ikke mod root eller tab af hele disken.

Der er ingen kendt resterende reproduceret fejl i den gennemførte testsuite. Det betyder ikke, at alle produktkrav er gennemført eller at uprøvede integrations-/installationsforløb er fejlfrie.

## 8. Før produktionsservere tilsluttes

1. Gennemfør native installation og genstart/afinstallation i en disponibel Ubuntu 24.04-VM.
2. Verificér de forskellige serviceidentiteter, PostgreSQL-grants, HTTPS/certifikatkæde, brokerpeer-adgang og at workers ikke kan skrive policy, kode, audit eller backup.
3. Konfigurér en faktisk model/provider, budgetter og få dokumenterede integrationer; test først med læserettigheder.
4. Enrol én ukritisk Linux-node. Sammenlign inventory med kendt OS-/Docker-/netværksstatus, og test offline/revocation.
5. Udfør rigtig backup, restore-drill, release-staging og uafhængig rollback på VM'en. Opbevar en separat recoverykopi og ejerens signeringsnøgle uden for AI-adgangen.
6. Tillad kun én konkret, ufarlig reparation med kort udløb og eksakte mål i både policy og broker. Mål før/efter og test fejlscenariet.
7. Afprøv ARM64, relevante eksterne API-versioner og ChatGPT-forbindelsen, inden de beskrives som understøttet i drift.
8. Forbind først kritiske produktionsservices efter disse målte kontroller. Udvid derefter præcise tilladelser gradvist; automatisk drift kræver opsætning, ikke gentagne godkendelser for hver læsning.
