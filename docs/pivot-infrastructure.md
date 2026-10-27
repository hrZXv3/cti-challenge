# Pivot d'infrastructure : mémo des commandes

Commandes pour enquêter sur un domaine malveillant en sources ouvertes, sans jamais visiter le site. Exemple d'application : [J02](../J02-pivot-vidar/).

## Prérequis

```bash
sudo apt install -y dnsutils whois jq curl
```
Installe `dig` (DNS), `whois`, `jq` (lecture du JSON) et `curl` (appels aux API).

```bash
set -a; source .env; set +a
```
Charge les clés API du fichier `.env` dans le terminal.

## Trouver une cible dans la collecte J01

```bash
cut -d, -f1 data/iocs.csv | grep -oE "https?://[^/:]+" | sed -E 's#https?://##' | awk -F. '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -rn | head -15
```
Affiche les 15 domaines qui reviennent le plus dans les URL collectées.

```bash
grep ",threatfox,Vidar," data/iocs.csv | cut -d, -f1,2 | head -20
```
Affiche les IOC d'une famille de malware donnée, avec leur type.

```bash
for d in exemple1.org exemple2.org; do
  echo "== $d"
  grep "$d" data/iocs.csv | cut -d, -f3,4 | sort | uniq -c
done
```
Affiche la source et la famille de malware associées à chaque domaine.

```bash
grep -oE "https?://[^/]+" data/iocs.csv | sed -E 's#https?://##' | grep -E "exemple1\.org|exemple2\.org" | sort | uniq -c | sort -rn
```
Liste les sous-domaines utilisés, avec leur nombre d'URL.

## DNS

```bash
dig +short A exemple.org
```
Donne l'adresse IP du domaine. Si c'est une IP Cloudflare (`104.21.x`, `172.67.x`, `188.114.96-97.x`), le partage d'IP ne prouve rien.

```bash
dig +short NS exemple.org
```
Donne les serveurs de noms. Chez Cloudflare, une même paire sur plusieurs domaines peut indiquer un même compte.

## Whois et RDAP

```bash
whois exemple.org | grep -iE "creation date|registrar:|registry expiry date"
```
Donne la date de création, le registrar et la date d'expiration.

```bash
curl -sL "https://rdap.org/domain/exemple.pro" | jq -r '.events[] | "\(.eventAction) \(.eventDate)"'
```
Donne les dates de création, d'expiration et de modification via RDAP, quand le whois ne répond pas.

```bash
curl -sL "https://rdap.org/domain/exemple.pro" | jq -r '.entities[] | select(.roles[] == "registrar") | .vcardArray[1][] | select(.[0] == "fn") | .[3]'
```
Donne le registrar via RDAP.

## Certificats (crt.sh)

```bash
curl -s --max-time 90 "https://crt.sh/?q=%25.exemple.org&output=json" | jq -r '.[] | "\(.not_before) \(.name_value)"' | sort -u | head -30
```
Liste les certificats du domaine et de ses sous-domaines, avec leur date. Des wildcards seuls (`*.exemple.org`) permettent de créer des sous-domaines à volonté.

## ThreatFox

```bash
curl -s -X POST https://threatfox-api.abuse.ch/api/v1/ -H "Auth-Key: $ABUSECH_API_KEY" -d '{"query":"search_ioc","search_term":"sous.exemple.org"}' | jq -r '.data[0:3][] | "\(.ioc) | \(.threat_type) | \(.malware_printable) | confiance: \(.confidence_level) | signalé par: \(.reporter) | \(.first_seen)"'
```
Donne le rôle de l'IOC (`botnet_cc` = C2, `payload_delivery` = distribution), la famille, la confiance, le signaleur et la date.

## VirusTotal

```bash
curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/domains/exemple.org" | jq -r '.data.attributes | "malveillant: \(.last_analysis_stats.malicious) | suspect: \(.last_analysis_stats.suspicious) | catégories: \(.categories | tostring)"'
```
Donne le nombre de détections et les catégories du domaine. 0 détection ne veut pas dire sain. Limite gratuite : 4 requêtes par minute.

Sur le site, l'onglet **Relations > Communicating Files** liste les fichiers malveillants qui contactent le domaine.

## Répéter une commande sur plusieurs domaines

```bash
for d in exemple1.org exemple2.org exemple3.org; do
  echo "== $d"
  dig +short NS "$d"
  sleep 3
done
```
Lance la même commande sur chaque domaine de la liste, avec une pause de 3 secondes entre chaque.

## En cas d'erreur

| Message | Solution |
|---|---|
| `command not found` | installer l'outil (`sudo apt install -y jq`, `dnsutils`…) |
| `jq: parse error` | le service a renvoyé une erreur : relancer plus tard |
| whois vide | passer par RDAP |
| réponse vide de l'API | recharger les clés avec `set -a; source .env; set +a` |
