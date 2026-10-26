# CTI Challenge - 25 projets CTI en 5 semaines

**Auteur :** Elijah Calonnec - 3e année Expert en Cybersécurité (OTERIA), majeure Renseignement & Cybermenaces
[LinkedIn](https://linkedin.com/in/elijahcal) - [Portfolio](https://hrzxv3.github.io/Elijah-Calonnec/)

Pendant que le reste de ma promo a rejoint son entreprise d'alternance, je suis toujours en recherche. Plutôt que d'attendre, je me suis lancé un défi : réaliser un projet de Cyber Threat Intelligence chaque jour ouvré, du 26 octobre au 27 novembre 2026. En entretien, on me demande souvent un projet mené de A à Z ; à la fin du défi, j'en aurai 25 à montrer.

Les projets couvrent les différentes facettes du métier : collecte et automatisation, investigation d'infrastructures malveillantes, analyse de malware, règles de détection, renseignement sur les acteurs et outillage.

Ils ne sont pas indépendants : les IOC collectés au premier jour sont ensuite enrichis, visualisés, convertis au format STIX puis importés dans une instance OpenCTI. L'objectif est de construire, projet après projet, une chaîne CTI complète, de la collecte jusqu'à l'exploitation.

Chaque dossier contient le code, la démarche suivie, les résultats obtenus et les limites identifiées. Le tableau ci-dessous est mis à jour au fil du défi, et un récapitulatif est publié chaque vendredi sur [LinkedIn](https://linkedin.com/in/elijahcal).

## Les 25 projets

Statut : à faire / en cours / fait

| Jour | Date | Projet | Compétences | Statut |
|---|---|---|---|---|
| J01 | 26/10 | [Agrégateur d'IOC (ThreatFox + URLhaus + OpenPhish -> CSV quotidien)](./J01-agregateur-ioc/) | Collecte, Python, API | fait |
| J02 | 27/10 | [Pivot complet sur une URL de phishing récente](./J02-pivot-phishing/) | Investigation infra, DNS, ASN | à faire |
| J03 | 28/10 | [3 règles YARA pour une famille de malware](./J03-regles-yara/) | Détection, YARA | à faire |
| J04 | 29/10 | [Fiche acteur d'un groupe ransomware + layer ATT&CK](./J04-fiche-acteur-ransomware/) | Renseignement, ATT&CK | à faire |
| J05 | 30/10 | [Dashboard Streamlit des IOC collectés (J01)](./J05-dashboard-ioc/) | Outillage, visualisation | à faire |
| J06 | 02/11 | [Enrichisseur d'IOC (IP/domaine -> rapport Markdown)](./J06-enrichisseur-ioc/) | Enrichissement, API | à faire |
| J07 | 03/11 | [Cartographie d'un kit de phishing visant une banque FR](./J07-kit-phishing-banque/) | Investigation, urlscan | à faire |
| J08 | 04/11 | [Fiche stealer : IOC + ATT&CK](./J08-fiche-stealer/) | Malware, sandbox | à faire |
| J09 | 05/11 | [Comparaison des TTP de deux groupes](./J09-comparaison-ttp/) | Renseignement, ATT&CK Navigator | à faire |
| J10 | 06/11 | [Bot Discord de veille (CERT-FR, ANSSI, presse cyber)](./J10-bot-veille-discord/) | Veille, automatisation | à faire |
| J11 | 09/11 | [Extracteur d'IOC en CLI (PDF/texte, defang/refang)](./J11-extracteur-ioc-cli/) | Outillage, parsing | à faire |
| J12 | 10/11 | [Chasse aux C2 sur Shodan / Hunt.io (JARM, certificats)](./J12-chasse-c2/) | Threat hunting, infra | à faire |
| J13 | 11/11 | [2 règles Sigma tirées d'un rapport public](./J13-regles-sigma/) | Détection, Sigma | à faire |
| J14 | 12/11 | [Timeline d'une fuite publique française](./J14-timeline-fuite/) | OSINT, analyse | à faire |
| J15 | 13/11 | [Conversion des IOC en bundle STIX 2.1](./J15-export-stix/) | Standards CTI, STIX | à faire |
| J16 | 16/11 | [Surveillance de typosquatting d'une marque FR (dnstwist + crt.sh)](./J16-surveillance-typosquatting/) | Brand protection, certificats | à faire |
| J17 | 17/11 | [Chaîne de redirection d'une campagne de malvertising](./J17-chaine-malvertising/) | Investigation web | à faire |
| J18 | 18/11 | [Analyse statique d'un LNK / document malveillant (REMnux)](./J18-analyse-lnk-remnux/) | Malware, analyse statique | à faire |
| J19 | 19/11 | [Résumé exécutif d'un rapport éditeur + IOC (outil J11)](./J19-resume-rapport-editeur/) | Reporting | à faire |
| J20 | 20/11 | [Instance OpenCTI en Docker + import du STIX de J15](./J20-opencti-docker/) | Plateforme CTI | à faire |
| J21 | 23/11 | [Analyse du JS obfusqué d'une page de phishing](./J21-js-obfusque/) | Analyse JS | à faire |
| J22 | 24/11 | [Chasse dans un PCAP public (Wireshark)](./J22-chasse-pcap/) | Réseau, forensic | à faire |
| J23 | 25/11 | [Mini-observatoire ransomware France](./J23-observatoire-ransomware/) | Cybercrime intelligence | à faire |
| J24 | 26/11 | [Bot Telegram d'enrichissement (sur J06)](./J24-bot-telegram-enrichissement/) | Outillage, automatisation | à faire |
| J25 | 27/11 | [Brief CTI de synthèse du mois](./J25-brief-cti-mensuel/) | Reporting, synthèse | à faire |

## Structure

```
cti-challenge/
├── shared/      code commun, construit au fil du défi
├── data/        données partagées entre projets (raw/ non versionné)
├── docs/        documentation générale
└── JXX-.../     un dossier par projet, chacun avec son README
```

## Installation

```bash
git clone https://github.com/hrZXv3/cti-challenge.git
cd cti-challenge
bash setup.sh            # crée le venv, installe les dépendances, crée .env
nano .env                # renseigner les clés API
```

## Cadre

- Uniquement des sources ouvertes et des services publics, en mode passif.
- Aucune interaction active avec une infrastructure malveillante, aucun téléchargement de données de victimes.
- Les échantillons de malware sont manipulés en VM isolée (REMnux), jamais exécutés hors sandbox.
- Les IOC publiés sont « defangés » (`hxxp`, `[.]`).
- Les attributions sont présentées avec un niveau de confiance explicite.
