# Guide Ultra-Avançé des Protocoles de Supervision, Collecte et Analyse Réseau

<img width="1024" height="427" alt="a371cc3f-677e-46f8-9dc2-1f84792e62bc" src="https://github.com/user-attachments/assets/2e300d5e-0a2a-44f1-b6b1-50ceac20d52e" />


**Auteur :** hackers_tchad  
**Date :** 2026  
**Version :** 2.0  
**Licence :** Usage éducatif, professionnel et recherche. Mention de l'auteur obligatoire pour redistribution.  

---

## Table des matières

1. [Introduction générale](#introduction-générale)
2. [SNMP - Simple Network Management Protocol](#snmp---simple-network-management-protocol)
3. [NetFlow / IPFIX / sFlow](#netflow--ipfix--sflow)
4. [Syslog](#syslog)
5. [Comparatif technique global](#comparatif-technique-global)
6. [Architectures et topologies](#architectures-et-topologies)
7. [Commandes de vérification et dépannage](#commandes-de-vérification-et-dépannage)
8. [Applications, outils et implémentations](#applications-outils-et-implémentations)
9. [Sécurité, attaques et contre-mesures](#sécurité-attaques-et-contre-mesures)
10. [Ressources, bibliographie et liens](#ressources-bibliographie-et-liens)
11. [Fiches de synthèse rapide](#fiches-de-synthèse-rapide)
12. [Annexes](#annexes)

---

## Introduction générale

La supervision, la collecte et l'analyse des flux réseau et des événements constituent des piliers fondamentaux de l'administration système et réseau, de la sécurité opérationnelle (SOC, SIEM) et de la gestion des performances. Trois familles de protocoles dominent ce domaine :

- **SNMP (Simple Network Management Protocol)** : supervision et gestion des équipements réseau et serveurs via des requêtes structurées et des traps.
- **NetFlow / IPFIX / sFlow** : collecte et analyse des flux réseau pour comprendre le trafic, détecter les anomalies et optimiser les performances.
- **Syslog** : standard de collecte centralisée des messages et événements système, applicatifs et de sécurité.

Ce guide explore en profondeur ces trois protocoles : définitions, historique, créateurs, architectures, mécanismes, configuration, commandes, utilisation, sécurité, outils, bibliographie et annexes pratiques. Il s'adresse aux administrateurs réseau, ingénieurs système, architectes sécurité, analystes SOC, étudiants en cybersécurité et à toute personne souhaitant maîtriser la supervision moderne.

> **Ligne de conduite :** SNMP, NetFlow et Syslog ne sont pas des concurrents mais des compléments. Une infrastructure de supervision robuste combine souvent les trois pour obtenir une vision temps réel de la santé, des performances et de la sécurité du réseau.

---

## TL;DR - Résumé exécutif

| Protocole | Couche OSI | Fonction principale | Transport | Port(s) | Statut |
|-----------|-----------|---------------------|-----------|---------|--------|
| **SNMP** | 7 (application) | Supervision et gestion des équipements | UDP (TCP possible) | 161 (queries), 162 (traps) | Actif, v3 recommandé |
| **NetFlow** | 7 (application) | Collecte de flux réseau | UDP | 2055, 9995, 6343 | Propriétaire Cisco, standardisé via IPFIX |
| **IPFIX** | 7 (application) | Standard ouvert de collecte de flux | UDP/SCTP | 4739 | Actif, standard IETF |
| **sFlow** | 7 (application) | Échantillonnage statistique de paquets | UDP | 6343 | Actif, standard IETF |
| **Syslog** | 7 (application) | Collecte centralisée de messages d'événements | UDP/TCP | 514 (legacy), 6514 (TLS) | Actif, standard IETF |

---

# 1. SNMP - Simple Network Management Protocol

## 1.1 Définition

**SNMP (Simple Network Management Protocol)** est un protocole standard de l'Internet utilisé pour superviser et gérer des équipements réseau tels que des routeurs, des switchs, des pare-feu, des serveurs, des imprimantes, des onduleurs, des caméras IP et de nombreux autres dispositifs connectés. SNMP permet de :

- **Lire** des informations sur l'état et les performances d'un équipement.
- **Configurer** certains paramètres à distance.
- **Recevoir des alertes** asynchrones (traps ou informs) lorsqu'un événement se produit.

SNMP repose sur un modèle agent-manager. L'**agent** est un processus qui s'exécute sur l'équipement supervisé et expose des données structurées. Le **manager** est l'application qui interroge les agents et centralise les informations.

## 1.2 Historique et créateurs

- **Créateurs :** IETF (Internet Engineering Task Force), avec des contributions initiales de nombreux ingénieurs réseau.
- **SNMPv1** : RFC 1157 (1990). Première version, communautés en clair, très répandue.
- **SNMPv2c** : RFC 1901 à 1908 (1996). Améliorations des performances et des types de données, mais authentification toujours basée sur les communautés.
- **SNMPv3** : RFC 3410 à 3418 (2002-2004). Ajout de la sécurité : authentification, intégrité et chiffrement.
- **SNMPv2u, SNMPv2* :** versions intermédiaires peu utilisées.
- **État actuel :** SNMPv3 est recommandé pour toute nouvelle installation. SNMPv1 et SNMPv2c restent utilisés pour des raisons de compatibilité mais sont considérés comme non sécurisés.

## 1.3 Architecture SNMP

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SNMP Manager (NMS)                           │
│                  (Zabbix, Nagios, LibreNMS, PRTG)                   │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ Requêtes SNMP (UDP 161)
                                │ Traps / Informs (UDP 162)
┌───────────────────────────────▼─────────────────────────────────────┐
│                        SNMP Agent                                   │
│              (routeur, switch, serveur, imprimante)                 │
├─────────────────────────────────────────────────────────────────────┤
│                        MIB (Management Information Base)            │
├─────────────────────────────────────────────────────────────────────┤
│                        OID (Object Identifier)                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Composants clés

| Composant | Description |
|-----------|-------------|
| **NMS (Network Management Station)** | Application ou serveur qui supervise les agents SNMP. |
| **Agent SNMP** | Processus sur l'équipement supervisé qui répond aux requêtes et envoie des traps. |
| **MIB (Management Information Base)** | Base de données hiérarchique décrivant les objets gérables. |
| **OID (Object Identifier)** | Identifiant unique d'un objet dans la MIB (ex: `1.3.6.1.2.1.1.1.0`). |
| **Community string** | Mot de passe partagé en SNMPv1/v2c (ex: `public`, `private`). |
| **Trap / Inform** | Message asynchrone envoyé par l'agent vers le manager. |
| **PDU (Protocol Data Unit)** | Unité de données échangée : GetRequest, GetNextRequest, GetResponse, SetRequest, Trap, Inform. |

## 1.4 Structure des MIB et OID

### Qu'est-ce qu'une MIB ?

Une **MIB (Management Information Base)** est une collection hiérarchique d'objets gérables. Chaque objet est identifié par un **OID (Object Identifier)**. La structure ressemble à un arbre DNS inversé.

### Arbre OID simplifié

```
1 (iso)
└── 3 (org)
    └── 6 (dod)
        └── 1 (internet)
            ├── 2 (mgmt) -> MIB-II
            │   └── 1 (mib-2)
            │       ├── 1 (system)
            │       ├── 2 (interfaces)
            │       ├── 3 (at)
            │       ├── 4 (ip)
            │       ├── 5 (icmp)
            │       ├── 6 (tcp)
            │       ├── 7 (udp)
            │       └── ...
            ├── 4 (private) -> enterprises
            │   └── 1 (enterprises)
            │       ├── 9 (cisco)
            │       ├── 11 (hp)
            │       ├── 2021 (net-snmp)
            │       └── ...
            └── 6 (snmpV2)
```

### OID courants (MIB-II)

| OID | Description |
|-----|-------------|
| `1.3.6.1.2.1.1.1.0` | sysDescr : description du système |
| `1.3.6.1.2.1.1.3.0` | sysUpTime : temps depuis le dernier démarrage |
| `1.3.6.1.2.1.1.5.0` | sysName : nom du système |
| `1.3.6.1.2.1.2.2.1.2.*` | ifDescr : description des interfaces |
| `1.3.6.1.2.1.2.2.1.10.*` | ifInOctets : octets reçus par interface |
| `1.3.6.1.2.1.2.2.1.16.*` | ifOutOctets : octets émis par interface |
| `1.3.6.1.2.1.25.1.6.0` | hrSystemProcesses : nombre de processus (Host MIB) |

### Exemple de nommage

```
SNMPv2-MIB::sysDescr.0 = STRING: Linux serveur 5.15.0-91-generic
```

## 1.5 Versions de SNMP

### SNMPv1

- Communautés en clair (`public`, `private`).
- Authentification inexistante.
- Types de données limités.
- Utilise des PDU Get, GetNext, Set, Trap.

### SNMPv2c

- Communautés en clair (comme v1).
- Ajout du PDU GetBulk pour de meilleures performances.
- Types de données améliorés (64-bit counters).
- Traps normalisés (SNMPv2-MIB).

### SNMPv3

- **USM (User-based Security Model)** : sécurité basée sur les utilisateurs.
- **VACM (View-based Access Control Model)** : contrôle d'accès basé sur les vues.
- **Authentification** : MD5 (déconseillé) ou SHA (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512).
- **Chiffrement** : DES (déconseillé), AES-128, AES-192, AES-256.
- **Niveaux de sécurité :**
  - `noAuthNoPriv` : sans authentification ni chiffrement.
  - `authNoPriv` : avec authentification, sans chiffrement.
  - `authPriv` : avec authentification et chiffrement (recommandé).

## 1.6 Mécanismes de fonctionnement

### Requêtes synchrones

Le manager envoie une requête à l'agent, qui répond immédiatement.

```
Manager --- GetRequest  ---> Agent
Manager <--- GetResponse --- Agent
```

Types de requêtes :
- **Get** : récupère la valeur d'un OID.
- **GetNext** : récupère la valeur de l'OID suivant dans la table.
- **GetBulk** : récupère un grand nombre de valeurs en une seule requête (v2c/v3).
- **Set** : modifie la valeur d'un OID.
- **Walk** : parcourt toute une branche de la MIB (basé sur GetNext).

### Traps et Informs

Les **traps** sont des messages asynchrones envoyés par l'agent au manager pour signaler un événement (démarrage, panne, seuil dépassé). Ils ne nécessitent pas d'accusé de réception.

Les **informs** sont similaires aux traps mais exigent un accusé de réception (plus fiables, plus lourds).

## 1.7 Installation et configuration SNMP

### Installation sur Debian/Ubuntu

```bash
# Agent SNMP
sudo apt update
sudo apt install snmp snmpd libsnmp-dev

# Outils client
sudo apt install snmp-mibs-downloader
```

### Installation sur CentOS/RHEL/Rocky

```bash
sudo dnf install net-snmp net-snmp-utils
```

### Configuration agent SNMPv3 sur Linux (`/etc/snmp/snmpd.conf`)

```bash
# Créer un utilisateur SNMPv3
sudo net-snmp-create-v3-user -ro -A "MonAuthPass123" -X "MonPrivPass123" -a SHA -x AES admin_snmp
```

Fichier de configuration minimal `/etc/snmp/snmpd.conf` :

```ini
# Agent accessible sur toutes les interfaces
agentAddress udp:161,udp6:[::1]:161

# Informations système
syslocation "Datacenter Paris"
syscontact "admin@example.com"
sysname "serveur-prod-01"

# Vues autorisées
view all included .1 80

# Accès SNMPv3
rouser admin_snmp authPriv -V all

# Désactiver SNMPv1/v2c
rocommunity disabled 127.0.0.1
```

Démarrer l'agent :

```bash
sudo systemctl enable --now snmpd
sudo systemctl status snmpd
```

### Configuration SNMPv3 sur Cisco IOS

```ios
snmp-server group ADMIN-GROUP v3 priv
snmp-server user admin ADMIN-GROUP v3 auth sha MonAuthPass123 priv aes 128 MonPrivPass123
snmp-server host 192.168.1.10 version 3 priv admin
snmp-server enable traps
snmp-server location "Datacenter Paris"
snmp-server contact "admin@example.com"
```

### Configuration SNMPv2c (legacy, à éviter)

```ios
snmp-server community MonCommunityString RO
snmp-server host 192.168.1.10 version 2c MonCommunityString
```

## 1.8 Commandes de vérification SNMP

### Depuis Linux

```bash
# Récupérer la description système (SNMPv2c)
snmpget -v2c -c public 192.168.1.1 1.3.6.1.2.1.1.1.0

# Récupérer le nom du système
snmpget -v2c -c public 192.168.1.1 SNMPv2-MIB::sysName.0

# Walk complet d'une branche
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.1

# Walk des interfaces
snmpwalk -v2c -c public 192.168.1.1 IF-MIB::ifTable

# SNMPv3
snmpwalk -v3 -u admin_snmp -l authPriv -a SHA -A MonAuthPass123 -x AES -X MonPrivPass123 192.168.1.1

# GetBulk
snmpbulkwalk -v2c -c public 192.168.1.1 IF-MIB::ifXTable

# Tester la connectivité SNMP
snmpget -v2c -c public 192.168.1.1 sysUpTime.0
```

### Dépannage

```bash
# Vérifier que l'agent écoute
sudo ss -lunp | grep 161

# Logs de snmpd
sudo journalctl -u snmpd -f

# Capturer les requêtes SNMP
sudo tcpdump -i any -n -v udp port 161 or udp port 162

# Vérifier les OID supportés
snmpwalk -v2c -c public localhost .1 | head -50
```

## 1.9 OIDs et MIBs spécialisés

### Host Resources MIB (RFC 2790)

| OID | Description |
|-----|-------------|
| `1.3.6.1.2.1.25.1.1.0` | hrSystemUptime |
| `1.3.6.1.2.1.25.1.6.0` | hrSystemProcesses |
| `1.3.6.1.2.1.25.2.3.1.*` | hrStorageTable (disques, RAM) |
| `1.3.6.1.2.1.25.3.3.1.2.*` | hrProcessorLoad (charge CPU) |

### Interface MIB (IF-MIB)

| OID | Description |
|-----|-------------|
| `1.3.6.1.2.1.2.2.1.2.*` | ifDescr |
| `1.3.6.1.2.1.2.2.1.5.*` | ifSpeed |
| `1.3.6.1.2.1.2.2.1.10.*` | ifInOctets |
| `1.3.6.1.2.1.2.2.1.16.*` | ifOutOctets |
| `1.3.6.1.2.1.31.1.1.1.6.*` | ifHCInOctets (64-bit) |
| `1.3.6.1.2.1.31.1.1.1.10.*` | ifHCOutOctets (64-bit) |

### Cisco enterprise MIBs

- CISCO-PROCESS-MIB : charge CPU Cisco.
- CISCO-MEMORY-POOL-MIB : mémoire Cisco.
- CISCO-ENVMON-MIB : température, ventilateurs, alimentations.
- CISCO-RTTMON-MIB : SLA et mesures IP SLA.

## 1.10 Utilisation de SNMP

- **Supervision des équipements réseau** : routeurs, switchs, pare-feu, WLAN controllers.
- **Supervision des serveurs** : CPU, mémoire, disques, processus, températures.
- **Gestion des imprimantes** : niveaux d'encre, état des trays, compteurs de pages.
- **Supervision des onduleurs** : état de la batterie, charge, tension.
- **IoT et industrie** : capteurs, automate, équipements connectés.
- **Capacity planning** : tendances d'utilisation, prévisions.
- **Alerting** : traps pour pannes, seuils, changements d'état.

## 1.11 Applications et outils SNMP

### Serveurs de supervision (NMS)

| Outil | Type | Caractéristiques |
|-------|------|------------------|
| **Zabbix** | Open source | Complète, templates SNMP intégrés, alerting avancée. |
| **Nagios / Icinga** | Open source | Modulaire, large communauté, plugins SNMP. |
| **LibreNMS** | Open source | Auto-discovery, polling SNMP, interface web moderne. |
| **PRTG** | Commercial | Facile d'utilisation, sonde SNMP native. |
| **SolarWinds NPM** | Commercial | Riche en fonctionnalités, coût élevé. |
| **Cacti** | Open source | Graphiques basés sur RRD, excellent pour la bande passante. |
| **Observium** | Open source / commercial | Auto-discovery, cartographie réseau. |
| **Checkmk** | Open source / commercial | Puissante, auto-discovery, dashboards. |
| **Datadog / New Relic** | Cloud / commercial | Intégration SNMP, monitoring cloud. |

### Outils en ligne de commande

- `snmpget`, `snmpwalk`, `snmpbulkwalk`, `snmpset`, `snmptranslate` (NET-SNMP).
- `snmpcheck` (Kali Linux, audit).
- `onesixtyone` (scanner de communautés SNMP).
- `braa` (walk SNMP rapide et parallèle).

## 1.12 Bonnes pratiques SNMP

- **Utiliser SNMPv3** avec authPriv (authentification + chiffrement).
- **Désactiver SNMPv1 et SNMPv2c** ou restreindre aux interfaces de loopback.
- **Utiliser des community strings complexes** si v1/v2c inévitables.
- **Restreindre l'accès** par ACL/IP aux managers autorisés.
- **Changer les community strings par défaut** (`public`, `private`).
- **Surveiller les tentatives d'accès** et les traps d'authentification échouée.
- **Maintenir les MIBs à jour** pour les équipements spécifiques.
- **Limiter les vues** (VACM) aux OID nécessaires.
- **Journaliser et auditer** régulièrement.

---

# 2. NetFlow / IPFIX / sFlow

## 2.1 Définition de NetFlow

**NetFlow** est une technologie propriétaire développée par Cisco pour collecter des informations sur les flux réseau. Un **flux (flow)** est défini comme un ensemble unidirectionnel de paquets partageant les mêmes caractéristiques (adresses IP source/destination, ports, protocole, interface, type de service, etc.).

NetFlow permet de :
- Comprendre la répartition du trafic réseau.
- Identifier les top talkers et les applications consommatrices.
- Détecter les anomalies et les menaces (DDoS, scans, exfiltration).
- Facturer et allouer des coûts par service ou département.
- Optimiser la qualité de service (QoS).

## 2.2 Historique et créateurs

- **Créateur :** Cisco Systems.
- **NetFlow v1** : première version interne (1990).
- **NetFlow v5** : version la plus répandue, ajout des champs AS, masques de sous-réseau, next-hop.
- **NetFlow v7** : spécifique à certaines plateformes Cisco (Catalyst).
- **NetFlow v8** : agrégation des flux.
- **NetFlow v9** : format flexible avec template-based records, support IPv6 et MPLS.
- **IPFIX (IP Flow Information Export)** : RFC 3917, 5101, 5102. Standard ouvert basé sur NetFlow v9.
- **sFlow** : RFC 3176. Technologie d'échantillonnage statistique concurrente, standard IETF.

## 2.3 Architecture NetFlow

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Collecteur / Analyseur NetFlow                   │
│            (nfdump, nfsen, Elastiflow, Plixer Scrutinizer)          │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ UDP 2055 / 9995 / 6343
┌───────────────────────────────▼─────────────────────────────────────┐
│                    Exporteur NetFlow                                │
│                  (routeur Cisco, switch, pare-feu)                  │
└─────────────────────────────────────────────────────────────────────┘
```

### Composants clés

| Composant | Description |
|-----------|-------------|
| **Exporteur (Exporter)** | Équipement réseau qui génère et envoie les flux. |
| **Collecteur (Collector)** | Serveur qui reçoit, stocke et indexe les flux. |
| **Analyseur (Analyzer)** | Application qui visualise et analyse les flux. |
| **Flux (Flow)** | Ensemble de paquets unidirectionnels avec des caractéristiques communes. |
| **Template** | Structure définissant les champs exportés (v9/IPFIX). |

### Clés d'identification d'un flux

- Adresse IP source.
- Adresse IP destination.
- Port source (TCP/UDP).
- Port destination (TCP/UDP).
- Protocole IP (TCP, UDP, ICMP, etc.).
- Type de service (ToS) / DSCP.
- Interface d'entrée.

## 2.4 Versions de NetFlow et IPFIX

### NetFlow v5

- Format fixe.
- Champs classiques : src/dst IP, ports, protocole, octets, paquets, flags TCP.
- Ne supporte pas IPv6 ni MPLS.
- Très répandu, compatible avec la plupart des collecteurs.

### NetFlow v9

- Format basé sur templates.
- Supporte IPv6, MPLS, BGP, multicast.
- Permet des champs personnalisés.

### IPFIX (NetFlow v10)

- Standard IETF (RFC 5101, 5102, 7011).
- Basé sur NetFlow v9.
- Supporte des champs utilisateur et des enterprises IDs.
- Transport UDP par défaut, SCTP possible.

### sFlow

- Échantillonnage statistique des paquets (1 sur N) et des compteurs.
- Ne conserve pas tous les flux mais donne une vision représentative.
- Plus léger sur le plan CPU que NetFlow.
- Supporte IPv6, VLAN, MPLS.

## 2.5 Mécanismes de fonctionnement

### Création d'un flux

Lorsqu'un paquet arrive sur l'interface d'un routeur, l'exporteur extrait les champs de la clé de flux. Si le flux existe déjà dans le cache, les compteurs sont mis à jour. Sinon, un nouveau flux est créé.

### Export des flux

Un flux est exporté vers le collecteur lorsque :
- Le flux est inactif depuis un certain temps (timeout inactif).
- Le flux est actif depuis trop longtemps (timeout actif).
- Le cache est plein.
- L'équipement redémarre.
- Un flag TCP FIN ou RST est détecté.

### Templates NetFlow v9/IPFIX

Les templates décrivent la structure des records de données. Ils sont envoyés périodiquement pour permettre au collecteur de décoder les flux.

```
Template FlowSet : définit les champs
Data FlowSet     : contient les valeurs
```

## 2.6 Configuration NetFlow

### Cisco IOS (NetFlow v9)

```ios
! Activer NetFlow sur l'interface
interface GigabitEthernet0/0
 ip flow ingress
 ip flow egress
!
! Définir le collecteur
ip flow-export version 9
ip flow-export destination 192.168.1.10 2055
ip flow-export source Loopback0
!
! Options supplémentaires
ip flow-cache timeout active 1
ip flow-cache timeout inactive 15
!
! Activer l'export des templates
ip flow-export template refresh-rate 20
ip flow-export template timeout-rate 30
```

### Cisco IOS (Flexible NetFlow)

```ios
flow record MON_RECORD
 match ipv4 source address
 match ipv4 destination address
 match transport source-port
 match transport destination-port
 match interface input
 collect counter bytes
 collect counter packets
!
flow exporter MON_EXPORTER
 destination 192.168.1.10
 source Loopback0
 transport udp 2055
 template data timeout 30
!
flow monitor MON_MONITOR
 record MON_RECORD
 exporter MON_EXPORTER
!
interface GigabitEthernet0/0
 ip flow monitor MON_MONITOR input
```

### MikroTik RouterOS

```rsc
/ip traffic-flow
set enabled=yes
/ip traffic-flow target
add dst-address=192.168.1.10 port=2055 version=9
/ip traffic-flow interface
add interface=ether1
```

### Linux avec softflowd

```bash
sudo apt install softflowd
sudo softflowd -i eth0 -n 192.168.1.10:2055 -v 9
```

### Linux avec pmacct / nprobe

- **pmacct** : suite de comptage et d'export de trafic.
- **nprobe** : exporteur NetFlow/IPFIX professionnel.

```bash
# pmacctd example
sudo pmacctd -i eth0 -c src_host,dst_host,src_port,dst_port,proto -P print
```

## 2.7 Configuration sFlow

### Cisco IOS

```ios
sflow collector 192.168.1.10
sflow source-interface Loopback0
sflow sampling-rate 1000
sflow poll-interval 30
!
interface GigabitEthernet0/0
 sflow flow sampling
 sflow counter sampling
```

### Switch HP / Arista / Juniper

La plupart des switches modernes supportent sFlow avec des commandes similaires :

```
sflow agent-ip 192.168.1.1
sflow collector 192.168.1.10
sflow polling 30
sflow sampling 1000
```

### Host sFlow

**Host sFlow** est un agent open source qui exporte des métriques système et réseau au format sFlow.

```bash
sudo apt install hsflowd
```

Configuration `/etc/hsflowd.conf` :

```ini
sflow {
  DNSSD = off
  polling = 30
  sampling = 1000
  collector { ip = 192.168.1.10 udpport = 6343 }
}
```

## 2.8 Commandes de vérification NetFlow / sFlow

### Cisco IOS

```ios
show ip cache flow
show ip flow interface
show ip flow export
show flow monitor name MONITOR
```

### Linux

```bash
# Vérifier que softflowd écoute et exporte
sudo systemctl status softflowd
sudo softflowctl statistics

# Capturer les paquets NetFlow
sudo tcpdump -i any -n -v udp port 2055

# Capturer les paquets sFlow
sudo tcpdump -i any -n -v udp port 6343

# Analyser avec nfdump
nfdump -R /var/cache/nfdump/2026/01/01
nfdump -R /var/cache/nfdump/ -s srcip
nfdump -R /var/cache/nfdump/ -n 10 -o extended
```

### Collecteur nfdump / nfsen

```bash
# Installer nfdump
sudo apt install nfdump

# Démarrer le collecteur
nfcapd -w -D -S 2 -l /var/cache/nfdump -p 2055

# Lister les flux
nfdump -R /var/cache/nfdump/

# Top 10 des IP sources
nfdump -R /var/cache/nfdump/ -s srcip -n 10

# Filtrer par port
nfdump -R /var/cache/nfdump/ 'port 443'
```

## 2.9 Utilisation de NetFlow / IPFIX / sFlow

- **Analyse du trafic** : top talkers, protocoles, applications.
- **Détection d'anomalies** : scans, DDoS, exfiltration, malware.
- **Capacity planning** : dimensionnement des liens.
- **Facturation et showback** : répartition des coûts réseau.
- **QoS et ingénierie du trafic** : optimisation des routes.
- **Forensics** : investigation post-incident.
- **Compliance** : traçabilité des flux.

## 2.10 Applications et outils NetFlow / sFlow

### Collecteurs et analyseurs

| Outil | Type | Caractéristiques |
|-------|------|------------------|
| **nfdump / nfsen** | Open source | Collecteur et visualisateur basé sur RRD. |
| **ElastiFlow** | Open source | Collecteur NetFlow/IPFIX/sFlow pour Elasticsearch. |
| **Plixer Scrutinizer** | Commercial | Analyse avancée, reporting, sécurité. |
| **SolarWinds NTA** | Commercial | Intégration avec NPM, dashboards. |
| **ManageEngine NetFlow Analyzer** | Commercial | Facile à déployer, riche en rapports. |
| **Akamai / Kentik** | Cloud / commercial | Analyse à grande échelle, détection DDoS. |
| **Flowmon** | Commercial | Analyse de flux, détection d'anomalies, NDR. |
| **Wireshark** | Open source | Décodage des paquets NetFlow/sFlow. |

### Outils d'export

- **softflowd** : exporteur NetFlow pour Linux.
- **pmacct** : comptage et export de trafic.
- **nprobe** : exporteur professionnel NetFlow/IPFIX.
- **fprobe** : exporteur NetFlow v5/v9.
- **host-sflow** : agent sFlow pour serveurs.

---

# 3. Syslog

## 3.1 Définition

**Syslog** est un standard de protocole utilisé pour transmettre des messages de journalisation (logs) d'équipements et d'applications vers un serveur de collecte centralisé. Il est largement utilisé dans les systèmes Unix/Linux, les équipements réseau, les pare-feu, les serveurs et les applications.

Syslog permet de :
- Centraliser les logs pour faciliter l'analyse et la corrélation.
- Déclencher des alertes en cas d'événements critiques.
- Archiver des preuves pour la conformité et la forensique.
- Alimenter des SIEM (Security Information and Event Management).

## 3.2 Historique et créateurs

- **Créateur initial :** Eric Allman, dans le cadre du projet Sendmail (années 1980).
- **Première standardisation :** RFC 3164 (2001) - "The BSD syslog Protocol".
- **Standardisation moderne :** RFC 5424 (2009) - "The Syslog Protocol", avec un format de message structuré.
- **Syslog over TLS :** RFC 5425 - Transport Layer Security Mapping.
- **État actuel :** Syslog est universellement supporté, bien que de nombreuses variantes propriétaires existent.

## 3.3 Architecture Syslog

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Collecteur Syslog / SIEM                         │
│           (rsyslog, syslog-ng, Splunk, ELK, Graylog, Wazuh)         │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ UDP 514 / TCP 514 / TCP 6514 (TLS)
┌───────────────────────────────▼─────────────────────────────────────┐
│                    Émetteurs Syslog                                 │
│       (serveurs Linux, routeurs, pare-feu, applications)            │
└─────────────────────────────────────────────────────────────────────┘
```

### Composants clés

| Composant | Description |
|-----------|-------------|
| **Émetteur (Sender)** | Équipement ou application qui génère les messages. |
| **Relais (Relay)** | Serveur qui retransmet les messages vers un collecteur. |
| **Collecteur (Collector)** | Serveur qui reçoit et stocke les logs. |
| **Facility** | Catégorie de l'émetteur (kernel, mail, daemon, etc.). |
| **Severity / Priority** | Niveau d'importance du message (DEBUG, INFO, WARNING, ERR, CRIT, etc.). |
| **Message** | Contenu textuel du log. |

## 3.4 Format des messages Syslog

### Format RFC 3164 (BSD Syslog)

```
<PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
```

Exemple :

```
<34>Oct 11 22:14:15 serveur sshd[12345]: Failed password for root from 192.168.1.100 port 22
```

- **PRI** : facility * 8 + severity. Ici 34 = 4 (auth) * 8 + 2 (crit).

### Format RFC 5424 (Syslog moderne)

```
<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
```

Exemple :

```
<34>1 2026-01-15T14:30:00.123Z serveur.example.com sshd 12345 - - Failed password for root
```

Avantages : timestamp ISO 8601, hostname, application, ID de processus, données structurées.

### Facilities (RFC 5424)

| Code | Facility |
|------|----------|
| 0 | kernel |
| 1 | user |
| 2 | mail |
| 3 | daemon |
| 4 | auth |
| 5 | syslog |
| 6 | lpr |
| 7 | news |
| 8 | uucp |
| 9 | cron |
| 10 | authpriv |
| 16-23 | local0 à local7 |

### Severities

| Code | Severity | Description |
|------|----------|-------------|
| 0 | Emergency | Système inutilisable |
| 1 | Alert | Action immédiate requise |
| 2 | Critical | Condition critique |
| 3 | Error | Condition d'erreur |
| 4 | Warning | Avertissement |
| 5 | Notice | Condition normale mais significative |
| 6 | Informational | Message informatif |
| 7 | Debug | Message de débogage |

## 3.5 Transport Syslog

### UDP 514

- Transport historique.
- Non fiable mais très répandu.
- Performant pour un grand volume de logs.

### TCP 514

- Transport fiable.
- Garantit l'ordre et la livraison.
- Utilisé par rsyslog, syslog-ng, collecteurs SIEM.

### TCP 6514 (Syslog over TLS)

- Chiffrement et authentification mutuelle via TLS.
- Recommandé pour les environnements sensibles.
- RFC 5425.

### RELP (Reliable Event Logging Protocol)

- Protocole fiable développé pour rsyslog.
- Garantit la livraison avec accusé de réception.
- Utilise TCP.

## 3.6 Installation et configuration Syslog

### rsyslog (Debian/Ubuntu/CentOS)

```bash
sudo apt install rsyslog
# ou
sudo dnf install rsyslog
```

Configuration serveur collecteur (`/etc/rsyslog.conf`) :

```ini
# Écouter en UDP
module(load="imudp")
input(type="imudp" port="514")

# Écouter en TCP
module(load="imtcp")
input(type="imtcp" port="514")

# Écouter en TLS (port 6514)
global(
    defaultNetstreamDriver="gtls"
    defaultNetstreamDriverCAFile="/etc/ssl/certs/ca.pem"
    defaultNetstreamDriverCertFile="/etc/ssl/certs/server-cert.pem"
    defaultNetstreamDriverKeyFile="/etc/ssl/private/server-key.pem"
)
module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1" StreamDriver.AuthMode="anon")
input(type="imtcp" port="6514")

# Séparer les logs par hôte émetteur
$template RemoteLogs,"/var/log/remote/%fromhost-ip%/%programname%.log"
*.* ?RemoteLogs
& ~
```

Configuration client (`/etc/rsyslog.d/99-forward.conf`) :

```ini
# Envoyer tous les logs vers le collecteur en TCP
*.* @@192.168.1.10:514

# Envoyer en TLS
$DefaultNetstreamDriver gtls
$DefaultNetstreamDriverCAFile /etc/ssl/certs/ca.pem
$DefaultNetstreamDriverCertFile /etc/ssl/certs/client-cert.pem
$DefaultNetstreamDriverKeyFile /etc/ssl/private/client-key.pem
$ActionSendStreamDriverAuthMode anon
$ActionSendStreamDriverMode 1
*.* @@192.168.1.10:6514
```

Redémarrer rsyslog :

```bash
sudo systemctl restart rsyslog
sudo systemctl status rsyslog
```

### syslog-ng

```bash
sudo apt install syslog-ng
```

Configuration collecteur (`/etc/syslog-ng/syslog-ng.conf`) :

```
@version: 3.35
@include "scl.conf"

source s_net {
    network(transport("udp") port(514));
    network(transport("tcp") port(514));
};

destination d_remote { file("/var/log/remote/${HOST}/${PROGRAM}.log" create-dirs(yes)); };

log { source(s_net); destination(d_remote); };
```

### Configuration Syslog sur Cisco IOS

```ios
logging host 192.168.1.10
logging trap informational
logging source-interface Loopback0
service timestamps log datetime msec
logging facility local0
```

### Configuration Syslog sur pfSense / OPNsense

```
Status > System Logs > Settings
- Activer l'envoi vers un serveur syslog distant.
- Saisir l'IP du collecteur.
- Choisir UDP ou TCP, TLS si disponible.
- Sélectionner les facilities à exporter.
```

## 3.7 Commandes de vérification Syslog

### Linux

```bash
# Voir les logs système en temps réel
sudo tail -f /var/log/syslog

# Filtrer par service
sudo journalctl -u sshd -f

# Filtrer par priorité
sudo journalctl -p err

# Voir les logs remote
sudo tail -f /var/log/remote/192.168.1.1/messages.log

# Tester l'envoi syslog manuellement
logger -n 192.168.1.10 -P 514 -t TEST "Message de test"

# Envoyer en TCP
logger -n 192.168.1.10 -T -P 514 "Message TCP de test"

# Vérifier les ports d'écoute
sudo ss -lunp | grep 514
sudo ss -ltnp | grep 514

# Capturer le trafic syslog
sudo tcpdump -i any -n -v udp port 514 or tcp port 514
```

### Dépannage

```bash
# Vérifier la syntaxe rsyslog
rsyslogd -N1

# Logs de rsyslog
sudo journalctl -u rsyslog -f

# Vérifier les erreurs TLS
sudo cat /var/log/syslog | grep rsyslog-gnutls
```

## 3.8 Utilisation de Syslog

- **Centralisation des logs** : serveurs, réseau, sécurité, applications.
- **SIEM** : alimentation de Splunk, ELK, Graylog, Wazuh, QRadar, Sentinel.
- **Alerting** : détection d'intrusion, pannes, erreurs critiques.
- **Forensique** : investigation post-incident.
- **Compliance** : conservation des preuves (RGPD, PCI-DSS, HIPAA, LPM).
- **Débogage applicatif** : suivi des événements applicatifs.
- **Capacity planning** : analyse des tendances.

## 3.9 Applications et outils Syslog

### Collecteurs et SIEM

| Outil | Type | Caractéristiques |
|-------|------|------------------|
| **rsyslog** | Open source | Collecteur Syslog natif Linux, haute performance. |
| **syslog-ng** | Open source / commercial | Flexible, puissant, support TLS/RELP. |
| **Splunk** | Commercial | SIEM leader, indexation puissante. |
| **ELK Stack** | Open source | Elasticsearch, Logstash, Kibana. |
| **Graylog** | Open source / commercial | SIEM moderne, dashboards, alerting. |
| **Wazuh** | Open source | SIEM/XDR, intégration agents et syslog. |
| **QRadar / Sentinel** | Commercial | SIEM entreprise. |
| **Loki** | Open source | Agrégation de logs cloud-native par Grafana. |

### Outils d'analyse

- `journalctl` (systemd).
- `grep`, `awk`, `sed`, `cut`.
- `logrotate` (rotation des logs).
- `goaccess`, `awstats` (logs web).
- `lnav` (visualiseur de logs interactif).

---

# 4. Comparatif technique global

| Critère | SNMP | NetFlow/IPFIX/sFlow | Syslog |
|---------|------|---------------------|--------|
| Objectif | Supervision état/performance | Analyse des flux réseau | Collecte de messages d'événements |
| Couche OSI | 7 | 7 | 7 |
| Transport | UDP 161/162 | UDP 2055/6343/4739 | UDP 514, TCP 514, TCP 6514 (TLS) |
| Direction | Manager -> Agent, Agent -> Manager (traps) | Équipement -> Collecteur | Émetteur -> Collecteur |
| Données | Métriques, états, tables | Flux réseau, paquets échantillonnés | Messages textuels |
| Granularité | Ponctuelle / polling | Flux agrégés / échantillonnés | Événements individuels |
| Volume | Faible à moyen | Élevé | Très élevé |
| Sécurité | SNMPv3 authPriv recommandé | IPFIX chiffré rare, sFlow en clair | Syslog over TLS (TCP 6514) recommandé |
| Cas d'usage | Supervision infrastructure | Analyse trafic, sécurité, capacité | SIEM, forensique, alerting |
| Standard | IETF | Cisco (NetFlow), IETF (IPFIX, sFlow) | IETF (RFC 3164, 5424, 5425) |

---

# 5. Architectures et topologies

## 5.1 Architecture de supervision centralisée

```
                         ┌─────────────────────┐
                         │   SIEM / NMS /      │
                         │   Plateforme de     │
                         │   supervision       │
                         └──────────┬──────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │ SNMP                │ Syslog              │ NetFlow
              │                     │                     │
       ┌──────▼──────┐       ┌──────▼──────┐       ┌──────▼──────┐
       │   Routeurs  │       │   Serveurs  │       │   Routeurs  │
       │   Switchs   │       │   Pare-feu  │       │   Pare-feu  │
       │   Serveurs  │       │   Apps      │       │   Switchs   │
       └─────────────┘       └─────────────┘       └─────────────┘
```

## 5.2 Architecture avec relais Syslog

```
Site distant A                          Site distant B
┌──────────────┐                       ┌──────────────┐
│ Serveurs     │───Syslog─────────────▶│ Relais       │
│ Routeurs     │                       │ Syslog       │
└──────────────┘                       └───────┬──────┘
                                               │
                                               │ TLS
                                               ▼
                                       ┌───────────────┐
                                       │ SIEM central  │
                                       │ (Splunk/ELK)  │
                                       └───────────────┘
```

## 5.3 Architecture NetFlow distribuée

```
Internet
   │
   ▼
[Border Router] ──NetFlow v9──▶ [Collecteur régional A]
   │
   ├── [Firewall] ──IPFIX──▶ [Collecteur régional B]
   │
   └── [Core Switch] ──sFlow──▶ [Collecteur régional C]
                                       │
                                       ▼
                              [Analyseur central / SIEM]
```

## 5.4 Architecture Zero Trust / SOC

- **SNMPv3** : supervision sécurisée des équipements.
- **Syslog over TLS** : collecte centralisée et immuable des événements.
- **NetFlow/IPFIX** : détection des menaces et anomalies réseau.
- **SIEM** : corrélation des événements, détection des incidents.
- **SOAR** : orchestration des réponses aux incidents.

---

# 6. Commandes de vérification et dépannage

## 6.1 Commandes générales réseau

```bash
# Vérifier les ports d'écoute
sudo ss -tunlp | grep -E '161|162|514|2055|6343|6514'

# Capturer le trafic SNMP
sudo tcpdump -i any -n -v udp port 161 or udp port 162

# Capturer le trafic NetFlow
sudo tcpdump -i any -n -v udp port 2055

# Capturer le trafic sFlow
sudo tcpdump -i any -n -v udp port 6343

# Capturer le trafic Syslog
sudo tcpdump -i any -n -v udp port 514 or tcp port 514 or tcp port 6514
```

## 6.2 Commandes SNMP

```bash
# Walk complet
snmpwalk -v2c -c public 192.168.1.1 .1

# Walk SNMPv3
snmpwalk -v3 -u admin -l authPriv -a SHA -A pass -x AES -X pass 192.168.1.1

# Scanner les communautés (test d'audit)
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 192.168.1.0/24

# Tester un OID
snmpget -v2c -c public 192.168.1.1 sysUpTime.0
```

## 6.3 Commandes NetFlow / sFlow

```bash
# Démarrer nfcapd
sudo nfcapd -D -S 2 -l /var/cache/nfdump -p 2055

# Lister les flux
sudo nfdump -R /var/cache/nfdump/

# Top talkers
sudo nfdump -R /var/cache/nfdump/ -s srcip -n 10

# Filtrer par protocole et port
sudo nfdump -R /var/cache/nfdump/ 'proto tcp and port 443'
```

## 6.4 Commandes Syslog

```bash
# Voir les logs en temps réel
sudo tail -f /var/log/syslog

# Envoyer un test
logger -n 192.168.1.10 "Test syslog message"

# Vérifier rsyslog
sudo rsyslogd -N1

# Voir les logs systemd
sudo journalctl -u rsyslog -f
```

## 6.5 Dépannage courant

| Problème | Cause probable | Solution |
|----------|---------------|----------|
| Pas de réponse SNMP | Community erronée, ACL, agent arrêté | Vérifier la chaîne, les ACL, le service |
| Traps non reçues | Port 162 bloqué, mauvaise IP manager | Ouvrir le pare-feu, vérifier la cible |
| NetFlow absent | Interface non configurée, collecteur inaccessible | Activer l'export, tester la connectivité |
| Syslog non reçu | Port bloqué, mauvaise IP, format rejeté | Vérifier le pare-feu, la config émetteur |
| Perte de logs | UDP non fiable | Passer en TCP ou RELP/TLS |
| Logs non parsés | Format propriétaire | Adapter les parseurs/patterns |

---

# 7. Applications, outils et implémentations

## 7.1 Supervision SNMP

- **Zabbix**, **LibreNMS**, **Observium**, **Cacti**, **Nagios**, **Icinga**, **Checkmk**, **PRTG**, **SolarWinds**.

## 7.2 Collecte et analyse de flux

- **nfdump/nfsen**, **ElastiFlow**, **Plixer**, **SolarWinds NTA**, **ManageEngine**, **Kentik**, **Flowmon**, **Wireshark**.

## 7.3 Collecte et SIEM Syslog

- **rsyslog**, **syslog-ng**, **Splunk**, **ELK**, **Graylog**, **Wazuh**, **Loki**, **Datadog**.

## 7.4 Outils de sécurité et audit

- **onesixtyone**, **snmpcheck**, **braa**, **nmap** (scripts SNMP), **Metasploit** (modules SNMP), **Wireshark**, **tcpdump**.

---

# 8. Sécurité, attaques et contre-mesures

## 8.1 Menaces communes

- **Écoute passive** : interception de communautés SNMP, de flux NetFlow ou de logs Syslog non chiffrés.
- **Usurpation d'identité** : spoofing du manager SNMP ou du collecteur Syslog.
- **Déni de service** : saturation du collecteur ou de l'agent.
- **Exfiltration de données** : utilisation des canaux de supervision pour voler des informations.
- **Attaques par dictionnaire** : bruteforce des community strings SNMP.
- **Falsification de logs** : injection de faux messages Syslog.

## 8.2 Contre-mesures par protocole

### SNMP

- Utiliser **SNMPv3 authPriv**.
- Désactiver SNMPv1/v2c.
- Restreindre les accès par ACL.
- Utiliser des mots de passe forts.
- Surveiller les tentatives d'accès.

### NetFlow / sFlow

- Filtrer les sources autorisées au collecteur.
- Utiliser des VPN ou des liens dédiés si possible.
- Activer l'authentification IPFIX si supportée.
- Surveiller les volumes anormaux.

### Syslog

- Utiliser **Syslog over TLS (TCP 6514)**.
- Authentifier mutuellement avec des certificats.
- Protéger l'intégrité des logs (signature, immuabilité).
- Limiter l'accès au collecteur.
- Anonymiser les données sensibles.

## 8.3 Checklist de durcissement

- [ ] SNMPv3 activé, v1/v2c désactivés.
- [ ] Communautés par défaut changées ou supprimées.
- [ ] Syslog over TLS configuré.
- [ ] Collecteur NetFlow protégé par ACL/firewall.
- [ ] Rotation et archivage des logs.
- [ ] Surveillance des anomalies.
- [ ] MFA sur les accès aux outils de supervision.
- [ ] Plans de réponse aux incidents.

---

# 9. Ressources, bibliographie et liens

## 9.1 RFCs essentielles

- RFC 1157 - SNMPv1
- RFC 1901 à 1908 - SNMPv2c
- RFC 3410 à 3418 - SNMPv3
- RFC 2578 - SMIv2
- RFC 2579 - Textual Conventions for SMIv2
- RFC 2580 - Conformance Statements for SMIv2
- RFC 2790 - Host Resources MIB
- RFC 2863 - Interface Group MIB
- RFC 3164 - BSD Syslog Protocol
- RFC 5424 - The Syslog Protocol
- RFC 5425 - TLS Transport Mapping for Syslog
- RFC 5426 - UDP Transport Mapping for Syslog
- RFC 5427 - Textual Conventions for Syslog Management
- RFC 3917 - Requirements for IP Flow Information Export
- RFC 5101 - Specification of the IPFIX Protocol
- RFC 5102 - Information Model for IPFIX
- RFC 7011 - Specification of the IPFIX Protocol for IPv6
- RFC 3176 - InMon Corporation's sFlow
- RFC 3954 - Cisco Systems NetFlow Services Export Version 9

## 9.2 Livres recommandés

- *Essential SNMP* - Douglas Mauro et Kevin Schmidt
- *SNMP, SNMPv2, SNMPv3, and RMON 1 and 2* - William Stallings
- *Network Flow Analysis* - Michael W. Lucas
- *The Practice of Network Security Monitoring* - Richard Bejtlich
- *Applied Network Security Monitoring* - Chris Sanders et Jason Smith
- *Logging and Log Management* - Anton Chuvakin, Kevin Schmidt, Christopher Phillips
- *The SIEM Evaluation Guide* - Anton Chuvakin
- *Network Security Assessment* - Chris McNab
- *Hacking Exposed: Network Security Secrets & Solutions* - Stuart McClure et al.
- *Practical Packet Analysis* - Chris Sanders

## 9.3 Liens utiles

- https://datatracker.ietf.org/
- https://www.net-snmp.org/
- https://www.oxidized.org/
- https://www.librenms.org/
- https://www.zabbix.com/
- https://nfdump.sourceforge.io/
- https://elasiflow.com/
- https://www.rsyslog.com/
- https://www.syslog-ng.com/
- https://www.splunk.com/
- https://www.elastic.co/
- https://www.graylog.org/
- https://wazuh.com/
- https://grafana.com/oss/loki/

## 9.4 Auteur et crédits

**Auteur :** hackers_tchad  
**Date de publication :** 2026  
**Contact :** hackers_tchad (réseaux sociaux et communautés techniques)  
**Remerciements :** IETF, Cisco Systems, NET-SNMP project, rsyslog team, syslog-ng team, Elastic, Grafana, Wazuh, communautés open source.

---

# 10. Fiches de synthèse rapide

## Fiche SNMP

- **Objectif :** Superviser et gérer des équipements réseau.
- **Port :** UDP 161 (requêtes), UDP 162 (traps).
- **Version recommandée :** SNMPv3 authPriv.
- **Concepts clés :** MIB, OID, agent, manager, trap, inform.
- **Outils :** snmpwalk, snmpget, Zabbix, LibreNMS, Nagios.
- **Cas d'usage :** Monitoring infrastructure, alerting, capacity planning.

## Fiche NetFlow / IPFIX

- **Objectif :** Collecter et analyser les flux réseau.
- **Port :** UDP 2055 (NetFlow), UDP 4739 (IPFIX).
- **Versions :** v5, v9, IPFIX (v10).
- **Concepts clés :** Flow, exporter, collector, analyzer, template.
- **Outils :** nfdump, nfsen, ElastiFlow, Plixer, SolarWinds NTA.
- **Cas d'usage :** Analyse trafic, détection DDoS, forensique, QoS.

## Fiche sFlow

- **Objectif :** Échantillonnage statistique de paquets et compteurs.
- **Port :** UDP 6343.
- **Avantages :** Léger, standard, support matériel large.
- **Outils :** sFlow-RT, Wireshark, Host sFlow.
- **Cas d'usage :** Supervision réseau à haute volumétrie.

## Fiche Syslog

- **Objectif :** Centraliser les messages d'événements.
- **Port :** UDP 514, TCP 514, TCP 6514 (TLS).
- **Standards :** RFC 3164, RFC 5424, RFC 5425.
- **Concepts clés :** Facility, severity, PRI, structured data.
- **Outils :** rsyslog, syslog-ng, Splunk, ELK, Graylog, Wazuh.
- **Cas d'usage :** SIEM, forensique, alerting, compliance.

---

# 11. Annexes

## Annexe A : Tableau des ports et protocoles

| Protocole | Transport | Port | Description |
|-----------|-----------|------|-------------|
| SNMP queries | UDP/TCP | 161 | Requêtes SNMP |
| SNMP traps | UDP/TCP | 162 | Traps et informs SNMP |
| NetFlow v5/v9 | UDP | 2055 | Export de flux Cisco |
| NetFlow v9 | UDP | 9995 | Port alternatif Cisco |
| IPFIX | UDP/SCTP | 4739 | Export standard de flux |
| sFlow | UDP | 6343 | Échantillonnage sFlow |
| Syslog legacy | UDP/TCP | 514 | Collecte de logs |
| Syslog over TLS | TCP | 6514 | Collecte sécurisée de logs |

## Annexe B : Exemple de walk SNMP complet

```bash
snmpwalk -v2c -c public 192.168.1.1 .1.3.6.1.2.1.1
```

Résultat typique :

```
SNMPv2-MIB::sysDescr.0 = STRING: Cisco IOS Software, C880 Software...
SNMPv2-MIB::sysObjectID.0 = OID: CISCO-PRODUCTS::C881G-K9
SNMPv2-MIB::sysUpTimeInstance = Timeticks: (1234567) 14 days, 6:56:07.00
SNMPv2-MIB::sysContact.0 = STRING: admin@example.com
SNMPv2-MIB::sysName.0 = STRING: routeur-edge-01
SNMPv2-MIB::sysLocation.0 = STRING: Datacenter Paris
```

## Annexe C : Modèle de configuration SNMPv3 sécurisée

```bash
# Créer un utilisateur SNMPv3
sudo net-snmp-create-v3-user -ro -A "Str0ngAuthPass!" -X "Str0ngPrivPass!" -a SHA-256 -x AES-256 monitor

# /etc/snmp/snmpd.conf
agentAddress udp:161,udp6:[::1]:161
syslocation "Datacenter Paris"
syscontact "admin@example.com"
view all included .1 80
rouser monitor authPriv -V all
```

## Annexe D : Modèle de configuration rsyslog TLS

### Générer les certificats

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/syslog-key.pem \
  -out /etc/ssl/certs/syslog-cert.pem
```

### Serveur collecteur

```ini
module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1" StreamDriver.AuthMode="anon")
input(type="imtcp" port="6514")
$template RemoteLogs,"/var/log/remote/%fromhost-ip%/%programname%.log"
*.* ?RemoteLogs
```

### Client

```ini
$DefaultNetstreamDriver gtls
$DefaultNetstreamDriverCAFile /etc/ssl/certs/ca.pem
$DefaultNetstreamDriverCertFile /etc/ssl/certs/client-cert.pem
$DefaultNetstreamDriverKeyFile /etc/ssl/private/client-key.pem
$ActionSendStreamDriverAuthMode anon
$ActionSendStreamDriverMode 1
*.* @@192.168.1.10:6514
```

## Annexe E : Script de scan SNMP avec Python

```python
#!/usr/bin/env python3
from pysnmp.hlapi import *

community = 'public'
ip = '192.168.1.1'

for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
    SnmpEngine(),
    CommunityData(community),
    UdpTransportTarget((ip, 161)),
    ContextData(),
    ObjectType(ObjectIdentity('1.3.6.1.2.1.1')),
    lexicographicMode=False):

    if errorIndication:
        print(errorIndication)
        break
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        break
    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))
```

## Annexe F : Modèle de dashboard Grafana

### Métriques SNMP

- Charge CPU par équipement.
- Utilisation mémoire.
- Bande passante par interface.
- Temps de disponibilité (sysUpTime).
- Température et état matériel.

### Métriques NetFlow

- Top 10 des IP sources et destinations.
- Protocoles les plus utilisés.
- Volume de trafic par port.
- Carte géographique des flux.
- Détection d'anomalies.

### Métriques Syslog

- Nombre de messages par severity.
- Événements par service.
- Alertes de sécurité.
- Tendances d'erreurs.

## Annexe G : Scénarios de laboratoire pratiques

### Lab 1 : Supervision SNMP avec Zabbix

**Objectif :** Superviser un routeur Cisco via SNMPv3.

**Étapes :**
1. Configurer SNMPv3 sur le routeur.
2. Installer Zabbix Server sur une VM Linux.
3. Ajouter le routeur comme hôte avec le template SNMP.
4. Configurer les macros {$SNMP_USER}, {$SNMP_AUTHPASS}, {$SNMP_PRIVPASS}.
5. Vérifier la découverte des interfaces et l'affichage des graphiques.

### Lab 2 : Collecte NetFlow avec nfdump

**Objectif :** Collecter et analyser des flux NetFlow v9 depuis un routeur.

**Étapes :**
1. Installer nfdump sur un serveur Linux.
2. Démarrer nfcapd sur le port 2055.
3. Configurer le routeur pour exporter NetFlow v9 vers le collecteur.
4. Attendre quelques minutes.
5. Lister les flux avec `nfdump -R /var/cache/nfdump/`.
6. Identifier le top 10 des IP destinations avec `-s dstip`.

### Lab 3 : Centralisation Syslog avec rsyslog

**Objectif :** Centraliser les logs de plusieurs serveurs Linux.

**Étapes :**
1. Configurer un serveur rsyslog pour écouter en TCP 514.
2. Configurer les clients pour envoyer leurs logs vers le serveur.
3. Vérifier la réception dans `/var/log/remote/`.
4. Ajouter TLS sur le port 6514.
5. Tester avec `logger`.

### Lab 4 : Corrélation SNMP + NetFlow + Syslog dans un SIEM

**Objectif :** Créer un scénario incident où un équipement génère un pic de trafic (NetFlow), une alerte SNMP (CPU élevée) et des logs d'erreur (Syslog).

**Étapes :**
1. Générer du trafic anormal depuis une machine de test.
2. Observer le pic dans les flux NetFlow.
3. Vérifier l'alerte SNMP sur la charge CPU.
4. Consulter les logs Syslog correspondants.
5. Corréler les trois sources dans le SIEM.

## Annexe H : Scripts d'automatisation

### Script de découverte SNMP

```bash
#!/bin/bash
# discover_snmp.sh - Découvrir les OID d'un équipement

IP=$1
COMMUNITY=${2:-public}

if [ -z "$IP" ]; then
    echo "Usage: $0 <IP> [community]"
    exit 1
fi

echo "[*] Découverte de $IP avec la communauté $COMMUNITY"
snmpwalk -v2c -c "$COMMUNITY" "$IP" .1.3.6.1.2.1.1
```

### Script de collecte NetFlow

```bash
#!/bin/bash
# start_nfcapd.sh - Démarrer le collecteur NetFlow

PORT=${1:-2055}
DIR=${2:-/var/cache/nfdump}

mkdir -p "$DIR"
nfcapd -D -S 2 -l "$DIR" -p "$PORT"
echo "Collecteur NetFlow actif sur le port $PORT"
```

### Script de test Syslog

```bash
#!/bin/bash
# test_syslog.sh - Envoyer des messages syslog de test

SERVER=$1
PORT=${2:-514}
PROTO=${3:-udp}

if [ -z "$SERVER" ]; then
    echo "Usage: $0 <server> [port] [udp|tcp]"
    exit 1
fi

if [ "$PROTO" == "tcp" ]; then
    logger -n "$SERVER" -P "$PORT" -T "Test syslog TCP $(date)"
else
    logger -n "$SERVER" -P "$PORT" "Test syslog UDP $(date)"
fi

echo "Message envoyé vers $SERVER:$PORT en $PROTO"
```

## Annexe I : Intégration DevOps

### Déploiement rsyslog avec Ansible

```yaml
---
- name: Deploy rsyslog collector
  hosts: syslog_servers
  become: yes
  tasks:
    - name: Install rsyslog
      apt:
        name: rsyslog
        state: present

    - name: Configure rsyslog to listen on TCP/UDP 514
      template:
        src: rsyslog-server.conf.j2
        dest: /etc/rsyslog.conf
      notify: restart rsyslog

    - name: Ensure rsyslog is running
      systemd:
        name: rsyslog
        state: started
        enabled: yes

  handlers:
    - name: restart rsyslog
      systemd:
        name: rsyslog
        state: restarted
```

### Déploiement collecteur NetFlow avec Docker

```yaml
version: '3.8'
services:
  nfcapd:
    image: chiradeep/nfcapd
    container_name: nfcapd
    ports:
      - "2055:2055/udp"
    volumes:
      - ./nfdump-data:/data
    command: ["-D", "-S", "2", "-l", "/data", "-p", "2055"]
    restart: unless-stopped
```

## Annexe J : Conformité et réglementation

### RGPD / GDPR

- Anonymiser les adresses IP et identifiants dans les logs lorsque possible.
- Définir une durée de conservation.
- Documenter les traitements.

### PCI-DSS

- Centraliser les logs des systèmes en scope.
- Protéger l'intégrité des logs.
- Conserver les logs au moins 1 an, dont 3 mois en ligne.

### LPM / NIS2

- Supervision continue des systèmes sensibles.
- Conservation et protection des traces.
- Signalement des incidents.

## Annexe K : FAQ technique

**Q : SNMPv1/v2c est-il encore utilisable ?**
R : Uniquement en environnement isolé et contrôlé. En production, privilégiez SNMPv3 authPriv.

**Q : Quelle différence entre NetFlow et sFlow ?**
R : NetFlow conserve tous les flux (ou les expire par timeout), tandis que sFlow échantillonne statistiquement les paquets.

**Q : Syslog en UDP ou TCP ?**
R : TCP est plus fiable. TLS (port 6514) est recommandé pour la sécurité.

**Q : Comment éviter la perte de logs ?**
R : Utilisez TCP, RELP ou Syslog over TLS, avec des files d'attente côté émetteur.

**Q : Puis-je superviser des équipements cloud avec SNMP ?**
R : Les clouds publics ne supportent généralement pas SNMP natif. Utilisez des agents, des API cloud ou des outils comme CloudWatch, Azure Monitor, GCP Monitoring.

## Annexe L : Tableau de décision

| Besoin | Protocole recommandé | Alternative |
|--------|----------------------|-------------|
| Supervision équipements réseau | SNMPv3 | API REST, agent propriétaire |
| Analyse trafic réseau | NetFlow/IPFIX | sFlow, packet capture |
| Collecte logs centralisée | Syslog over TLS | Agent SIEM natif, API |
| Détection d'anomalies | NetFlow + Syslog | IDS/IPS, NDR |
| Alerting temps réel | SNMP traps + Syslog | Webhooks, API |

## Annexe M : Glossaire étendu

- **Agent** : Processus SNMP sur l'équipement supervisé.
- **Collector** : Serveur qui reçoit NetFlow, sFlow ou Syslog.
- **Community string** : Mot de passe partagé SNMPv1/v2c.
- **Facility** : Catégorie d'émetteur Syslog.
- **Flow** : Ensemble de paquets unidirectionnels NetFlow.
- **MIB** : Management Information Base.
- **NMS** : Network Management Station.
- **OID** : Object Identifier.
- **PDU** : Protocol Data Unit.
- **Severity** : Niveau d'importance Syslog.
- **Trap** : Message asynchrone SNMP.
- **Template** : Structure de données NetFlow v9/IPFIX.
- **USM** : User-based Security Model (SNMPv3).
- **VACM** : View-based Access Control Model (SNMPv3).

## Annexe N : Modèle de documentation d'architecture de supervision

```markdown
# Architecture de Supervision - [Nom du projet]

## 1. Contexte
[Description du besoin]

## 2. Sources de données
- SNMP : [équipements supervisés]
- NetFlow/IPFIX : [routeurs/exporteurs]
- Syslog : [serveurs, pare-feu, applications]

## 3. Collecteurs
- SNMP : [Zabbix, LibreNMS]
- NetFlow : [nfdump, ElastiFlow]
- Syslog : [rsyslog, Splunk, ELK]

## 4. Sécurité
- SNMPv3 authPriv.
- Syslog over TLS (TCP 6514).
- ACL sur les collecteurs NetFlow.

## 5. Alerting
- Seuils SNMP.
- Anomalies NetFlow.
- Corrélation Syslog.

## 6. Contacts
- Auteur : hackers_tchad
- Date : 2026
```

## Annexe O : Exercices pratiques pour apprenants

1. Configurer SNMPv3 sur un routeur et interroger avec `snmpwalk`.
2. Découvrir les OID d'un serveur Linux avec `snmpwalk`.
3. Configurer un export NetFlow v9 et analyser avec `nfdump`.
4. Déployer un collecteur rsyslog et centraliser les logs de 3 serveurs.
5. Mettre en place Syslog over TLS.
6. Créer un dashboard Grafana avec des métriques SNMP.
7. Détecter une attaque par scan de ports via NetFlow.
8. Corréler une alerte SNMP avec un événement Syslog.
9. Auditer une configuration SNMP avec `onesixtyone`.
10. Rédiger une politique de collecte et de conservation des logs.

## Annexe P : Checklist d'audit supervision

- [ ] Inventaire des équipements supervisés.
- [ ] Versions SNMP et niveaux de sécurité.
- [ ] Communautés par défaut supprimées.
- [ ] Collecteurs protégés par ACL.
- [ ] Syslog chiffré (TLS).
- [ ] Rotation et archivage des logs.
- [ ] Alertes configurées et testées.
- [ ] Dashboards à jour.
- [ ] Procédures d'incident documentées.
- [ ] Conformité réglementaire vérifiée.

## Annexe Q : Historique des vulnérabilités majeures

| Année | Vulnérabilité | Impact |
|-------|---------------|--------|
| 2002 | SNMP community strings par défaut | Accès non autorisé massif |
| 2013 | CVE-2012-2148 (SNMP) | DoS potentiel |
| 2016 | CVE-2016-1459 (Cisco SNMP) | Élévation de privilèges |
| 2018 | CVE-2018-1000119 (rsyslog) | Fuite d'informations |
| 2020 | Vulnérabilités SNMP dans équipements IoT | Botnets, accès non autorisé |
| 2022 | CVE-2022-24834 (Redis) via syslog | Injection de logs |
| 2023 | Diverses failles de parsing syslog | DoS, exécution de code |

## Annexe R : Communautés et ressources en ligne

- https://www.net-snmp.org/
- https://www.rsyslog.com/
- https://www.syslog-ng.com/
- https://nfdump.sourceforge.io/
- https://www.elastic.co/
- https://www.splunk.com/
- https://grafana.com/
- https://wazuh.com/
- https://www.librenms.org/
- https://www.zabbix.com/
- https://www.reddit.com/r/networking/
- https://serverfault.com/
- https://security.stackexchange.com/

## Annexe S : Feuille de route 2026-2027

- Adoption croissante de SNMPv3 et suppression progressive de v1/v2c.
- Standardisation et déploiement d'IPFIX dans les réseaux modernes.
- Généralisation de Syslog over TLS et des logs structurés (RFC 5424).
- Intégration des données de supervision dans les SIEM et les plateformes XDR.
- Utilisation de l'IA/ML pour la détection d'anomalies sur NetFlow et Syslog.
- Migration vers des agents cloud-native et des API REST pour la supervision hybride.

## Annexe T : Auteur et crédits finaux

**Auteur :** hackers_tchad  
**Date :** 2026  
**Version :** 2.0  
**Contact :** hackers_tchad (réseaux sociaux et communautés techniques)  
**Remerciements :** IETF, Cisco Systems, NET-SNMP project, rsyslog team, syslog-ng team, Elastic, Grafana, Wazuh, et l'ensemble des communautés open source.

---

**Fin du guide ultra-avancé sur SNMP, NetFlow et Syslog. Pour toute question, contribution ou correction, contactez hackers_tchad.**
