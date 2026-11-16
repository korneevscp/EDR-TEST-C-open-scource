# MiniEDR

MiniEDR est un prototype d'Endpoint Detection and Response (EDR) écrit en C pour Windows. Il collecte de la télémétrie processus et fichiers, attribue un score de risque à chaque événement et produit des journaux JSON directement exploitables par un SIEM (Elastic, Splunk, Wazuh, Graylog, Sentinel…).

> **Statut : prototype / projet expérimental.** MiniEDR ne remplace pas Microsoft Defender ni un EDR commercial.

## Fonctionnalités

| Module | Rôle |
|---|---|
| `process.c` | Inventaire des processus, surveillance des créations/arrêts en temps réel, enrichissement (chemin, ligne de commande, parent, SHA-256, signature) |
| `scanner.c` | Analyse récursive d'un répertoire (sans suivre les points de réparation) |
| `monitor.c` | Surveillance d'intégrité de fichiers (FIM) via `ReadDirectoryChangesW` asynchrone |
| `edr.c` | Moteur de règles et scoring multi-indicateurs, SHA-256 (CNG/BCrypt), vérification Authenticode |
| `logger.c` | Journal JSON Lines (champs de type ECS), rotation à 50 Mo, envoi UDP vers un SIEM |
| `main.c` | Menu console, options de ligne de commande, arrêt propre par `Ctrl+C` |

Le mode **Real-time protection** exécute en parallèle la surveillance des processus et celle d'un répertoire.

## Moteur de détection

Chaque indicateur ajoute des points ; le total (plafonné à 100) donne le niveau :

| Score | Niveau |
|---:|---|
| 0 | NONE |
| 1–29 | LOW |
| 30–59 | MEDIUM |
| 60–89 | HIGH |
| 90–100 | CRITICAL |

Règles processus :

- `known_attack_tool` : outils offensifs connus (mimikatz, rubeus, lazagne, psexec, procdump…)
- `lolbin` : binaires système détournables (powershell, mshta, rundll32, regsvr32, certutil…)
- `office_spawned_shell` : LOLBin lancé par Word, Excel, Outlook, Acrobat…
- `user_writable_path` : exécution depuis Temp, Downloads, Public, Corbeille…
- `system_name_masquerade` : nom de processus système (svchost, lsass…) hors du répertoire Windows
- `suspicious_cmdline` : PowerShell encodé, téléchargement, `-w hidden`, bypass, `certutil -urlcache`…
- `destructive_or_credential_cmdline` : suppression des clichés instantanés, dump de LSASS…
- `unsigned` : binaire suspect sans signature Authenticode valide

Règles fichiers : `malicious_keyword`, `rtlo_spoofing`, `script`, `double_extension` (ex. `facture.pdf.exe`), `pe_user_writable_path`, `unsigned`.

Les opérations coûteuses (hash, signature) ne sont réalisées que sur les éléments déjà suspects, ce qui garde le scan rapide.

## Intégration SIEM

Chaque événement est une ligne JSON dans `edr.jsonl` :

```json
{"@timestamp":"2026-11-16T09:18:05.419Z","event.sequence":335,"host.name":"PC01","agent.type":"MiniEDR","agent.version":"3.0.0","event.module":"scanner","event.action":"file_detected","event.kind":"alert","event.risk_score":95,"event.severity":4,"risk.level":"CRITICAL","rule.name":"double_extension,pe_user_writable_path,unsigned","file.path":"C:\\Users\\Public\\invoice.pdf.exe","file.name":"invoice.pdf.exe","file.size":2,"file.hash.sha256":"73cb...","file.code_signature.valid":false}
```

`event.kind` vaut `alert` à partir du niveau MEDIUM. Actions émises : `agent_started`, `process_inventory`, `process_started`, `process_stopped`, `process_scan_completed`, `file_detected`, `scan_completed`, `file_created`, `file_modified`, `file_deleted`, `file_renamed_from`, `file_renamed_to`, `monitor_overflow`…

Envoi direct vers un collecteur (Logstash, Fluent Bit, Wazuh, Graylog GELF/raw UDP…) :

```bat
MiniEDR.exe --siem 192.168.1.10:5514 --log C:\EDR\edr.jsonl
```

Le fichier peut aussi être lu par un agent (Filebeat, Splunk UF, Wazuh agent).

## Compilation

Prérequis : Windows 10+, GCC MinGW-w64 (ex. celui fourni avec Code::Blocks).

```bat
build.bat
```

Équivalent à :

```bat
gcc -O2 -std=c11 -Wall -Wextra -D_WIN32_WINNT=0x0A00 main.c edr.c logger.c process.c scanner.c monitor.c -o MiniEDR.exe -lbcrypt -lwintrust -lws2_32
```

Le projet Code::Blocks `MiniEDR.cbp` est configuré avec les mêmes options.

## Utilisation

```text
1. Process scan
2. File scan (recursive)
3. Directory monitoring
4. Process monitoring
5. Real-time protection (processes + directory)
6. Exit
```

`Ctrl+C` arrête le mode en cours et revient au menu. Lancer en administrateur permet de lire le chemin et la ligne de commande des processus protégés.

## Limitations

- Surveillance des processus par interrogation (250 ms) : les processus très courts peuvent être manqués. Une version pilotée par ETW ou un pilote noyau serait plus fiable.
- La vérification de signature ne couvre que les signatures intégrées ; les binaires signés par catalogue hors du répertoire Windows apparaissent comme non signés.
- Pas de blocage, de quarantaine, de télémétrie réseau ni d'analyse mémoire.
- Règles codées en dur, sans moteur YARA/Sigma.

## Licence

MIT, voir [LICENSE](LICENSE).

## Auteur

Projet développé par **korneevscp** — https://github.com/korneevscp/EDR-TEST-C-open-scource
