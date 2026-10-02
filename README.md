# MiniEDR

MiniEDR est un prototype d'Endpoint Detection and Response (EDR) développé en C pour Windows. Le projet fournit une base légère et lisible pour expérimenter les mécanismes fondamentaux de détection, de surveillance et de journalisation d'événements sur un poste Windows.

> **Statut : prototype / projet expérimental**
>
> MiniEDR ne doit pas être considéré comme un produit EDR complet ni comme une solution de sécurité prête pour un environnement de production. Les mécanismes de détection actuels reposent principalement sur des règles et des correspondances de noms.

## Objectifs

Le projet a pour objectif de réunir, dans une application console simple, plusieurs fonctions représentatives d'un EDR :

- énumération des processus Windows ;
- attribution d'un niveau de risque aux processus détectés ;
- analyse de fichiers dans un répertoire ;
- surveillance en temps réel des changements d'un répertoire ;
- génération d'un journal d'événements ;
- compilation native avec GCC et intégration Code::Blocks.

L'objectif principal est pédagogique et orienté expérimentation autour de la sécurité endpoint et de la programmation système Windows en C.

## Fonctionnalités

### Analyse des processus

Le module `process.c` utilise les API Windows Tool Help pour énumérer les processus actifs.

Pour chaque processus, MiniEDR affiche :

- le PID ;
- le nom de l'exécutable ;
- le niveau de risque associé.

Des noms de processus spécifiques peuvent déclencher une alerte élevée, notamment :

- `mimikatz`
- `psexec`
- `procdump`

Certaines familles d'outils ou d'interpréteurs, comme PowerShell, Windows Script Host et CScript, sont actuellement classées comme risque faible.

### Analyse de fichiers

Le module `scanner.c` permet d'analyser les fichiers présents dans un répertoire donné.

Le moteur de scoring examine notamment :

- certaines extensions de script ;
- certains noms associés à des outils ou contenus de test ;
- des mots-clés comme `payload` ou `shellcode`.

Le scanner affiche le fichier, son niveau de risque et le nombre total d'alertes détectées.

### Surveillance de répertoire

Le module `monitor.c` s'appuie sur `ReadDirectoryChangesW` afin d'observer les événements sur un répertoire Windows.

Les événements suivis incluent notamment :

- création de fichiers ;
- suppression ;
- modification ;
- renommage ;
- changements de taille.

Lorsqu'un événement est observé, MiniEDR applique le moteur de scoring des fichiers et écrit l'événement dans le journal.

### Journalisation

Le module `logger.c` centralise l'écriture des événements dans `edr.log`.

Chaque entrée contient :

- la date et l'heure ;
- le niveau de journalisation ;
- la source ;
- le message associé.

Exemple :

```text
[2026-10-01 11:21:24] [INFO] [PROCESS] Process scan completed
```

Les niveaux utilisés dans le projet comprennent notamment :

- `INFO`
- `EVENT`
- `ALERT`
- `ERROR`

## Niveaux de risque

Le moteur de scoring définit les niveaux suivants :

| Niveau | Valeur | Description |
|---|---:|---|
| NONE | 0 | Aucun indicateur détecté |
| LOW | 1 | Indicateur faible ou comportement nécessitant une analyse complémentaire |
| MEDIUM | 2 | Niveau intermédiaire prévu par l'architecture |
| HIGH | 3 | Indicateur considéré comme fortement suspect |
| CRITICAL | 4 | Niveau critique prévu par l'architecture |

Dans l'implémentation actuelle, les niveaux `MEDIUM` et `CRITICAL` existent dans l'API mais ne sont pas réellement utilisés par les règles de scoring fournies.

## Architecture

Le projet est organisé en modules C distincts afin de séparer les responsabilités.

```text
.
├── main.c
├── edr.c
├── edr.h
├── process.c
├── process.h
├── scanner.c
├── scanner.h
├── monitor.c
├── monitor.h
├── logger.c
├── logger.h
├── build.bat
├── MiniEDR.cbp
├── MiniEDR.layout
├── edr.log
├── bin/
├── obj/
└── LICENSE
```

### Rôle des modules

| Fichier | Responsabilité |
|---|---|
| `main.c` | Interface console et orchestration des modules |
| `edr.c / edr.h` | Logique de scoring et niveaux de risque |
| `process.c / process.h` | Énumération et analyse des processus |
| `scanner.c / scanner.h` | Analyse de fichiers et répertoires |
| `monitor.c / monitor.h` | Surveillance des changements de fichiers |
| `logger.c / logger.h` | Journalisation des événements |
| `build.bat` | Compilation rapide sous Windows |
| `MiniEDR.cbp` | Projet Code::Blocks |

## Prérequis

Le projet cible actuellement Windows et utilise les API natives Win32.

Pour compiler avec le script fourni, il faut disposer de :

- Windows ;
- GCC accessible depuis le terminal ;
- un environnement de développement C compatible C11.

Le projet Code::Blocks est également fourni via `MiniEDR.cbp`.

## Compilation avec GCC

Depuis une invite de commandes Windows :

```bat
build.bat
```

Le script exécute une compilation équivalente à :

```bat
gcc main.c edr.c logger.c process.c scanner.c monitor.c -Wall -Wextra -std=c11 -o MiniEDR.exe
```

En cas de succès, l'exécutable `MiniEDR.exe` est généré à la racine du projet.

## Compilation avec Code::Blocks

Ouvrez :

```text
MiniEDR.cbp
```

Deux configurations sont prévues :

- `Debug`
- `Release`

La chaîne de compilation utilise GCC avec :

```text
-Wall
-Wextra
-std=c11
```

Le projet lie également `kernel32`, utilisé par les composants Win32 du programme.

## Utilisation

L'exécutable démarre sur un menu console :

```text
===============================================
                 MiniEDR V2
===============================================
1. Process scan
2. File scan
3. File monitoring
4. Full scan
5. Exit
>
```

### Process scan

L'option `1` analyse les processus actuellement présents sur le système.

### File scan

L'option `2` demande un répertoire puis analyse les fichiers directement présents dans celui-ci.

### File monitoring

L'option `3` demande un répertoire et active une surveillance continue des changements.

L'arrêt du mode de surveillance s'effectue avec `Ctrl+C`.

### Full scan

L'option `4` enchaîne :

1. l'analyse des processus ;
2. l'analyse du répertoire courant.

## Modèle de détection

Le moteur actuel est volontairement simple. Il repose essentiellement sur des correspondances textuelles insensibles à la casse.

Exemples de règles présentes dans le code :

```text
Processus :
mimikatz  -> HIGH
psexec    -> HIGH
procdump  -> HIGH
powershell -> LOW
wscript    -> LOW
cscript    -> LOW

Fichiers :
.ps1 -> LOW
.vbs -> LOW
.js  -> LOW
.hta -> LOW
mimikatz -> HIGH
payload  -> HIGH
shellcode -> HIGH
```

Cette approche est utile pour démontrer le fonctionnement d'un moteur de règles, mais elle ne permet pas à elle seule de déterminer si un programme est réellement malveillant.

## Limitations connues

MiniEDR reste volontairement minimal. Plusieurs limites importantes doivent être prises en compte :

- détection principalement basée sur les noms et extensions ;
- absence d'analyse comportementale avancée ;
- absence de moteur de réputation ou d'intelligence de menace ;
- absence d'analyse mémoire ;
- absence de télémétrie réseau ;
- absence de persistance ou de service Windows dédié ;
- absence de mécanisme de blocage ou de quarantaine ;
- pas de corrélation avancée entre événements ;
- couverture limitée des techniques d'évasion ;
- pas de signature numérique ou de validation cryptographique des fichiers ;
- pas de véritable moteur heuristique ou comportemental.

En conséquence, le projet ne remplace pas Microsoft Defender ou une solution EDR commerciale dans un environnement réel.

## Sécurité et usage

Ce projet est destiné à l'apprentissage, au développement et aux tests dans des environnements contrôlés.

Les règles présentes dans MiniEDR permettent d'étudier certains concepts de détection endpoint, mais elles ne constituent pas une base suffisante pour assurer la protection complète d'un système.

Avant toute expérimentation sur une machine réelle, il est recommandé de comprendre les effets du monitoring de répertoires et des opérations d'énumération de processus.

## Journalisation et confidentialité

Le programme écrit les événements dans `edr.log`. Ce fichier peut contenir des informations relatives aux processus et aux fichiers observés.

Dans un déploiement réel, la gestion des journaux devrait prendre en compte :

- la rétention ;
- la rotation des logs ;
- les permissions d'accès ;
- l'intégrité des journaux ;
- la centralisation ;
- la protection contre leur suppression ou leur modification.

## Pistes d'évolution

Les prochaines évolutions possibles pour transformer ce prototype en plateforme de détection plus complète comprennent :

- ajout de règles configurables ;
- calcul de score multi-indicateurs ;
- analyse des chemins et arguments de processus ;
- surveillance des créations de processus ;
- collecte de hashes ;
- vérification de signatures Authenticode ;
- détection d'anomalies ;
- corrélation temporelle des événements ;
- télémétrie réseau ;
- analyse mémoire ;
- mécanisme de quarantaine ;
- export JSON ;
- interface graphique ;
- service Windows ;
- intégration SIEM ;
- tests automatisés ;
- pipeline CI/CD ;
- système de configuration centralisé.

## Développement

Le code est structuré afin de permettre l'ajout progressif de nouveaux moteurs de détection sans transformer `main.c` en composant monolithique.

Les interfaces sont séparées dans des fichiers `.h`, tandis que les implémentations sont conservées dans les fichiers `.c`.

Cette organisation facilite notamment :

- la maintenance ;
- les tests unitaires futurs ;
- l'ajout de nouveaux modules ;
- la réutilisation du moteur de scoring ;
- l'évolution vers une architecture plus complète.

## Licence

Le projet est distribué sous licence MIT.

Voir le fichier [LICENSE](LICENSE) pour le texte complet de la licence.

## Auteur

Projet développé par **korneevscp**.

Dépôt GitHub :

https://github.com/korneevscp/EDR-TEST-C-open-scource
