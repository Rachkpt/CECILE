# CECILE
# 🛡️ Suricata Guard — Installation Manuelle (Détection + Blocage)

> Déploiement manuel de Suricata avec règles personnalisées, blocage automatique via iptables et Fail2ban.
> Sans Telegram, sans Email — détection et blocage uniquement.
>
> **Signé : 12ak_H4ck**

---

## 📋 Vue d'ensemble

| Composant | Rôle |
|---|---|
| **Suricata** | Analyse du trafic réseau en temps réel |
| **local.rules** | Règles de détection personnalisées (NMAP, DDoS, brute-force, etc.) |
| **iptables / SURICATA_GUARD** | Chaîne dédiée pour le blocage automatique des IPs |
| **Fail2ban** | Bannissement automatique basé sur les logs noyau iptables |
| **suricata_guard.py** | Monitore `fast.log` et déclenche les blocages iptables |
| **systemd** | Maintien des services actifs au démarrage |

---

## ⚙️ Prérequis

- Ubuntu / Debian (apt)
- Accès root
- Les fichiers `suricata_guard.py` et `local.rules` dans le même dossier que ce README

---

## Étape 1 — Installation des paquets système

```bash
sudo apt-get update -y
sudo apt-get install -y software-properties-common
```

### Installer Suricata (PPA officiel OISF)

```bash
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt-get update -y
sudo apt-get install -y suricata
```

### Installer les outils complémentaires

```bash
sudo apt-get install -y iptables iptables-persistent net-tools curl jq fail2ban
sudo apt-get install -y python3 python3-pip python3-venv
sudo pip3 install --break-system-packages suricata-update
```

---

## Étape 2 — Configuration de Suricata

### 2.1 Sauvegarder la config par défaut

```bash
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
```

### 2.2 Définir l'interface réseau à surveiller

Identifier ton interface réseau principale :

```bash
ip route | grep default
# Exemple de résultat : default via 192.168.1.1 dev eth0
```

Éditer le fichier de configuration :

```bash
sudo nano /etc/suricata/suricata.yaml
```

Trouver la section `af-packet` et remplacer l'interface par la tienne :

```yaml
af-packet:
  - interface: eth0       # ← remplace eth0 par ton interface
```

### 2.3 Vérifier que fast.log est activé

Dans le même fichier `suricata.yaml`, section `outputs` :

```yaml
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
```

### 2.4 Copier les règles personnalisées

> ⚠️ **Suricata 7+ (et 8.x) cherche les règles dans `/var/lib/suricata/rules/` par défaut — PAS dans `/etc/suricata/rules/`.
> C'est ce chemin qu'il faut utiliser pour éviter le warning `No rule files match`.**

```bash
sudo mkdir -p /var/lib/suricata/rules
sudo cp local.rules /var/lib/suricata/rules/local.rules
```

Vérifier que le fichier est bien en place :

```bash
ls -la /var/lib/suricata/rules/local.rules
```

### 2.5 Ajouter local.rules à la configuration

```bash
sudo nano /etc/suricata/suricata.yaml
```

Trouver la section `rule-files` et ajouter `local.rules` :

```yaml
rule-files:
  - suricata.rules
  - local.rules          # ← ajouter cette ligne
```

> Si la section `default-rule-path` est présente dans `suricata.yaml`, vérifier qu'elle pointe bien vers `/var/lib/suricata/rules` :
>
> ```yaml
> default-rule-path: /var/lib/suricata/rules
> ```

### 2.6 Ajouter les règles ICMP / Ping dans local.rules

Ouvrir le fichier de règles :

```bash
sudo nano /var/lib/suricata/rules/local.rules
```

Ajouter les règles suivantes à la fin du fichier :

```
# ════════════════════════════════════════════════════════════════
#  RÈGLES ICMP / PING — 12ak_H4ck
# ════════════════════════════════════════════════════════════════

# ── PING ICMP ECHO REQUEST (détection simple, silencieux) ───────
alert icmp any any -> $HOME_NET any (msg:"PING ICMP - Echo request détecté"; itype:8; icode:0; classtype:misc-activity; sid:3400300; priority:3; rev:1;)

# ── PING ICMP ECHO REPLY ────────────────────────────────────────
alert icmp any any -> any any (msg:"PING ICMP - Echo reply"; itype:0; icode:0; classtype:misc-activity; sid:3400301; priority:3; rev:1;)

# ── ICMP FLOOD (volume élevé — DDoS) ────────────────────────────
alert icmp any any -> any any (msg:"ICMP FLOOD DDOS detecte"; itype:8; threshold:type threshold, track by_src, count 50, seconds 5; classtype:attempted-dos; sid:3400302; priority:1; rev:1;)

# ── ICMP OVERSIZED (ping of death) ──────────────────────────────
alert icmp any any -> any any (msg:"ICMP OVERSIZED - Ping of Death potentiel"; dsize:>1000; classtype:attempted-dos; sid:3400303; priority:1; rev:1;)

# ── NMAP PING SWEEP (-sP / -sn) ─────────────────────────────────
alert icmp any any -> $HOME_NET any (msg:"NMAP PING SWEEP - Scan réseau ICMP"; itype:8; threshold:type threshold, track by_src, count 5, seconds 2; classtype:attempted-recon; sid:3400304; priority:2; rev:1;)

# ── TRACEROUTE (TTL expired) ─────────────────────────────────────
alert icmp any any -> any any (msg:"TRACEROUTE ICMP - Sondage réseau détecté"; itype:11; icode:0; threshold:type threshold, track by_src, count 3, seconds 10; classtype:attempted-recon; sid:3400305; priority:2; rev:1;)
```

Sauvegarder et quitter (`Ctrl+X`, `Y`, `Entrée`).

### 2.7 Mettre à jour les règles Suricata

```bash
sudo suricata-update
```

### 2.8 Tester la configuration

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -i eth0
# Résultat attendu : "Configuration provided was successfully loaded."
```

---

## Étape 3 — Configuration complète iptables

### 3.1 Vider les règles existantes (fresh install uniquement)

```bash
sudo iptables -F
sudo iptables -X
```

> ⚠️ Ne pas faire ça sur un serveur en production si des règles importantes existent déjà.

### 3.2 Règles de base — autoriser le trafic légitime

```bash
# Autoriser le loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Autoriser les connexions déjà établies
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Autoriser SSH (évite de te couper du serveur)
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

### 3.3 Créer la chaîne dédiée SURICATA_GUARD

```bash
sudo iptables -N SURICATA_GUARD
```

### 3.4 Relier la chaîne à INPUT et FORWARD

```bash
sudo iptables -I INPUT   1 -j SURICATA_GUARD
sudo iptables -I FORWARD 1 -j SURICATA_GUARD
```

### 3.5 Détection et blocage des scans de ports

```bash
# ── SCAN NULL (aucun flag TCP) — nmap -sN ──────────────────────
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE \
  -m recent --name PORTSCAN --set \
  -j LOG --log-prefix "PORTSCAN-NULL: " --log-level 4
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# ── SCAN XMAS (FIN+PSH+URG) — nmap -sX ────────────────────────
sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG \
  -m recent --name PORTSCAN --set \
  -j LOG --log-prefix "PORTSCAN-XMAS: " --log-level 4
sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP

# ── SCAN FIN — nmap -sF ────────────────────────────────────────
sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN \
  -m recent --name PORTSCAN --set \
  -j LOG --log-prefix "PORTSCAN-FIN: " --log-level 4
sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN -j DROP

# ── SYN+RST invalide (évasion) ─────────────────────────────────
sudo iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST \
  -m recent --name PORTSCAN --set \
  -j LOG --log-prefix "PORTSCAN-SYNRST: " --log-level 4
sudo iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

# ── SYN+FIN invalide (évasion) ─────────────────────────────────
sudo iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN \
  -m recent --name PORTSCAN --set \
  -j LOG --log-prefix "PORTSCAN-SYNFIN: " --log-level 4
sudo iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

# ── SCAN UDP — nmap -sU ────────────────────────────────────────
sudo iptables -A INPUT -p udp \
  -m multiport --dports 53,67,68,69,123,161,500,1900 \
  -m recent --name PORTSCAN --set \
  -j LOG --log-prefix "PORTSCAN-UDP: " --log-level 4

# ── SCAN LENT -T0/-T1 (évasion timing) — 20 hits / 300 sec ────
sudo iptables -A INPUT -p tcp --syn \
  -m multiport --dports 21,22,23,25,80,443,3306,8080,9000,9200 \
  -m recent --name SLOWSCAN --set

sudo iptables -A INPUT -p tcp --syn \
  -m recent --name SLOWSCAN --rcheck --seconds 300 --hitcount 20 \
  -j LOG --log-prefix "PORTSCAN-SLOW: " --log-level 4

sudo iptables -A INPUT -p tcp --syn \
  -m recent --name SLOWSCAN --rcheck --seconds 300 --hitcount 20 \
  -j DROP

# ── SCAN RAPIDE -T4/-T5 — nmap -sS (5 SYN en 5 secondes) ──────
sudo iptables -A INPUT -p tcp --syn \
  -m multiport --dports 21,22,23,25,80,443,3306,8080,9000,9200 \
  -m recent --name PORTSCAN --set

sudo iptables -A INPUT -p tcp --syn \
  -m recent --name PORTSCAN --rcheck --seconds 5 --hitcount 5 \
  -j LOG --log-prefix "PORTSCAN-FAST: " --log-level 4

sudo iptables -A INPUT -p tcp --syn \
  -m recent --name PORTSCAN --rcheck --seconds 5 --hitcount 5 \
  -j DROP
```

### 3.6 Blocage global des IPs détectées pendant 1 heure

```bash
# Toute IP listée dans PORTSCAN bloquée 3600 secondes
sudo iptables -A INPUT \
  -m recent --name PORTSCAN --rcheck --seconds 3600 --hitcount 5 \
  -j DROP

# Toute IP listée dans SLOWSCAN bloquée 3600 secondes
sudo iptables -A INPUT \
  -m recent --name SLOWSCAN --rcheck --seconds 3600 --hitcount 20 \
  -j DROP
```

### 3.7 Détection DDoS et Flood

```bash
# ── ICMP FLOOD ─────────────────────────────────────────────────
sudo iptables -A INPUT -p icmp --icmp-type echo-request \
  -m limit --limit 1/s --limit-burst 10 -j ACCEPT
sudo iptables -A INPUT -p icmp --icmp-type echo-request \
  -j LOG --log-prefix "ICMP-FLOOD: " --log-level 4
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# ── SYN FLOOD ──────────────────────────────────────────────────
sudo iptables -A INPUT -p tcp --syn \
  -m limit --limit 25/s --limit-burst 50 -j ACCEPT
sudo iptables -A INPUT -p tcp --syn \
  -j LOG --log-prefix "SYN-FLOOD: " --log-level 4
sudo iptables -A INPUT -p tcp --syn -j DROP

# ── UDP FLOOD ──────────────────────────────────────────────────
sudo iptables -A INPUT -p udp \
  -m limit --limit 50/s --limit-burst 100 -j ACCEPT
sudo iptables -A INPUT -p udp \
  -j LOG --log-prefix "UDP-FLOOD: " --log-level 4
sudo iptables -A INPUT -p udp -j DROP
```

### 3.8 Brute-force SSH via iptables

```bash
# Limite à 3 nouvelles connexions SSH par minute par IP
sudo iptables -A INPUT -p tcp --dport 22 \
  -m state --state NEW \
  -m recent --name SSH_BRUTE --set

sudo iptables -A INPUT -p tcp --dport 22 \
  -m state --state NEW \
  -m recent --name SSH_BRUTE --rcheck --seconds 60 --hitcount 4 \
  -j LOG --log-prefix "SSH-BRUTE: " --log-level 4

sudo iptables -A INPUT -p tcp --dport 22 \
  -m state --state NEW \
  -m recent --name SSH_BRUTE --rcheck --seconds 60 --hitcount 4 \
  -j DROP
```

### 3.9 Sauvegarder les règles (persistance au redémarrage)

```bash
sudo netfilter-persistent save
```

### 3.10 Vérifier toutes les règles en place

```bash
# Toutes les règles avec compteurs
sudo iptables -L -n -v --line-numbers

# Chaîne SURICATA_GUARD uniquement
sudo iptables -L SURICATA_GUARD -n -v --line-numbers

# Chaîne INPUT uniquement
sudo iptables -L INPUT -n -v --line-numbers
```

---

## Étape 4 — Configuration Fail2ban

Fail2ban surveille les logs du noyau (kernel) générés par les règles iptables LOG
et banni automatiquement les IPs détectées via une action iptables complémentaire.

### 4.1 Créer le filtre de détection

```bash
sudo nano /etc/fail2ban/filter.d/portscan.conf
```

Coller le contenu suivant :

```ini
[Definition]
failregex = PORTSCAN.* SRC=<HOST>
            PORTSCAN-NULL.* SRC=<HOST>
            PORTSCAN-XMAS.* SRC=<HOST>
            PORTSCAN-FIN.* SRC=<HOST>
            PORTSCAN-SYNRST.* SRC=<HOST>
            PORTSCAN-SYNFIN.* SRC=<HOST>
            PORTSCAN-UDP.* SRC=<HOST>
            PORTSCAN-SLOW.* SRC=<HOST>
            PORTSCAN-FAST.* SRC=<HOST>
            SYN-FLOOD.* SRC=<HOST>
            ICMP-FLOOD.* SRC=<HOST>
            SSH-BRUTE.* SRC=<HOST>

ignoreregex =

[Init]
datepattern = {^LN-BEG}
```

### 4.2 Créer la jail dédiée aux scans de ports

```bash
sudo nano /etc/fail2ban/jail.d/portscan.conf
```

Coller le contenu suivant :

```ini
[portscan]
enabled      = true
filter       = portscan
backend      = systemd
journalmatch = _TRANSPORT=kernel
maxretry     = 5
findtime     = 60
bantime      = 3600
action       = iptables-allports[name=portscan, protocol=all]
```

### 4.3 Configurer le fichier jail.local global

```bash
sudo nano /etc/fail2ban/jail.local
```

Coller le contenu suivant :

```ini
[DEFAULT]
bantime   = 3600
findtime  = 60
maxretry  = 5
backend   = systemd
ignoreip  = 127.0.0.1/8 ::1
banaction = iptables-multiport
banaction_allports = iptables-allports

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 3
bantime  = 86400
```

### 4.4 Activer et démarrer Fail2ban

```bash
sudo systemctl enable fail2ban
sudo systemctl restart fail2ban
```

### 4.5 Vérifier que les jails sont actives

```bash
sudo fail2ban-client status
sudo fail2ban-client status portscan
sudo fail2ban-client status sshd
```

---

## Étape 5 — Déploiement du script Python (suricata_guard.py)

### 5.1 Créer le dossier de destination

```bash
sudo mkdir -p /opt/suricata-guard
```

### 5.2 Copier le script

```bash
sudo cp suricata_guard.py /opt/suricata-guard/suricata_guard.py
```

### 5.3 Éditer les paramètres dans le script

```bash
sudo nano /opt/suricata-guard/suricata_guard.py
```

Modifier les valeurs suivantes directement dans le fichier :

```python
ALERT_THRESHOLD  = 5          # Nombre d'alertes avant blocage automatique

TELEGRAM_TOKEN   = "DISABLED"
TELEGRAM_CHAT_ID = 0

EMAIL_ENABLED    = False
```

Ajouter les IPs à ne jamais bloquer dans la whitelist :

```python
WHITELIST = {
    "127.0.0.1",
    "::1",
    "192.168.1.1",    # ← exemple : ta passerelle
    "10.0.0.5",       # ← exemple : ton IP d'admin
}
```

### 5.4 Sécuriser les permissions du script

```bash
sudo chmod 700 /opt/suricata-guard/suricata_guard.py
sudo chown root:root /opt/suricata-guard/suricata_guard.py
```

### 5.5 Créer l'environnement Python virtuel

```bash
python3 -m venv /opt/suricata-guard/venv
/opt/suricata-guard/venv/bin/pip install --upgrade pip
/opt/suricata-guard/venv/bin/pip install "python-telegram-bot>=20,<21"
```

> La bibliothèque `python-telegram-bot` est installée car le script l'importe,
> mais le bot Telegram ne sera pas actif puisque le token est désactivé.

---

## Étape 6 — Création du service systemd

### 6.1 Créer le fichier service

```bash
sudo nano /etc/systemd/system/suricata-guard.service
```

Coller le contenu suivant :

```ini
[Unit]
Description=Suricata Guard - Blocage IP automatique (by 12ak_H4ck)
After=network.target suricata.service
Wants=suricata.service

[Service]
Type=simple
ExecStart=/opt/suricata-guard/venv/bin/python3 /opt/suricata-guard/suricata_guard.py
Restart=always
RestartSec=5
User=root
StandardOutput=append:/var/log/suricata_guard_service.log
StandardError=append:/var/log/suricata_guard_service.log

[Install]
WantedBy=multi-user.target
```

### 6.2 Recharger systemd et activer les services

```bash
sudo systemctl daemon-reload
sudo systemctl enable suricata
sudo systemctl enable suricata-guard
```

---

## Étape 7 — Démarrage de tous les services

```bash
# Suricata
sudo systemctl restart suricata
sleep 3
sudo systemctl status suricata

# Suricata Guard
sudo systemctl restart suricata-guard
sleep 3
sudo systemctl status suricata-guard

# Fail2ban
sudo systemctl restart fail2ban
sleep 2
sudo systemctl status fail2ban
```

---

## ✅ Vérifications post-installation

### Vérifier les services

```bash
sudo systemctl status suricata
sudo systemctl status suricata-guard
sudo systemctl status fail2ban
```

### Suivre les logs du guard en direct

```bash
journalctl -u suricata-guard -f
```

### Voir les alertes Suricata en temps réel

```bash
sudo tail -f /var/log/suricata/fast.log
```

### Voir les logs noyau iptables en direct

```bash
sudo journalctl -k -f | grep -E "PORTSCAN|FLOOD|BRUTE"
```

### Voir les IPs actuellement bloquées par iptables

```bash
# Chaîne SURICATA_GUARD
sudo iptables -L SURICATA_GUARD -n -v --line-numbers

# Toute la chaîne INPUT
sudo iptables -L INPUT -n -v --line-numbers
```

### Voir les IPs dans les listes recent

```bash
sudo cat /proc/net/xt_recent/PORTSCAN
sudo cat /proc/net/xt_recent/SLOWSCAN
sudo cat /proc/net/xt_recent/SSH_BRUTE
```

### Voir les IPs bannies par Fail2ban

```bash
sudo fail2ban-client status portscan
sudo fail2ban-client status sshd
```

### Voir le log des blocages Suricata Guard

```bash
sudo cat /var/log/suricata_blocked.log
sudo tail -f /var/log/suricata_blocked.log
```

---

## 🔧 Gestion manuelle des IPs bloquées

### ── Via iptables / SURICATA_GUARD ────────────────────────────

```bash
# Voir toutes les IPs bloquées avec leur numéro de ligne
sudo iptables -L SURICATA_GUARD -n -v --line-numbers

# Bloquer une IP manuellement
sudo iptables -A SURICATA_GUARD -s IP_A_BLOQUER -j DROP

# Débloquer une IP spécifique (par son adresse)
sudo iptables -D SURICATA_GUARD -s IP_A_DEBLOQUER -j DROP

# Débloquer une IP par son numéro de ligne (ex: ligne 3)
sudo iptables -D SURICATA_GUARD 3

# Vider toute la chaîne SURICATA_GUARD (débloquer tout)
sudo iptables -F SURICATA_GUARD

# Sauvegarder après toute modification manuelle
sudo netfilter-persistent save
```

### ── Via les listes recent iptables ───────────────────────────

```bash
# Retirer TOUTES les IPs de la liste PORTSCAN
echo / | sudo tee /proc/net/xt_recent/PORTSCAN

# Retirer TOUTES les IPs de la liste SLOWSCAN
echo / | sudo tee /proc/net/xt_recent/SLOWSCAN

# Retirer TOUTES les IPs de la liste SSH_BRUTE
echo / | sudo tee /proc/net/xt_recent/SSH_BRUTE

# Retirer UNE IP précise d'une liste (ex: 1.2.3.4 de PORTSCAN)
echo -1.2.3.4 | sudo tee /proc/net/xt_recent/PORTSCAN
```

### ── Via Fail2ban ──────────────────────────────────────────────

```bash
# Voir toutes les IPs bannies dans la jail portscan
sudo fail2ban-client status portscan

# Voir toutes les IPs bannies dans la jail sshd
sudo fail2ban-client status sshd

# Débannir une IP spécifique de la jail portscan
sudo fail2ban-client set portscan unbanip IP_A_DEBANNIR

# Débannir une IP spécifique de la jail sshd
sudo fail2ban-client set sshd unbanip IP_A_DEBANNIR

# Voir les logs Fail2ban en direct
sudo tail -f /var/log/fail2ban.log

# Recharger Fail2ban après modification de config
sudo fail2ban-client reload
```

---

## 🧪 Test de détection (depuis une autre machine)

### Ping avant scan (doit fonctionner)

```bash
ping IP_SERVEUR
# Résultat attendu : réponse normale ✅
```

### Lancer différents types de scans

```bash
# Scan SYN rapide (T4 par défaut)
nmap -sS IP_SERVEUR

# Scan lent évasion timing
nmap -sS -T1 IP_SERVEUR

# Scan NULL
nmap -sN IP_SERVEUR

# Scan XMAS
nmap -sX IP_SERVEUR

# Scan FIN
nmap -sF IP_SERVEUR

# Scan UDP
sudo nmap -sU IP_SERVEUR
```

### Ping après scan (doit être bloqué)

```bash
ping IP_SERVEUR
# Résultat attendu : 100% packet loss ❌
```

### Vérifier le blocage côté serveur

```bash
# IPs bloquées dans SURICATA_GUARD
sudo iptables -L SURICATA_GUARD -n -v

# Logs de détection noyau
sudo journalctl -k --since "5 minutes ago" | grep PORTSCAN

# IPs mémorisées dans les listes recent
sudo cat /proc/net/xt_recent/PORTSCAN

# Status Fail2ban
sudo fail2ban-client status portscan

# Log Suricata Guard
sudo cat /var/log/suricata_blocked.log
```

---

## 📁 Fichiers importants

| Fichier | Rôle |
|---|---|
| `/etc/suricata/suricata.yaml` | Configuration principale Suricata |
| `/var/lib/suricata/rules/local.rules` | Règles de détection personnalisées (chemin par défaut Suricata 7+/8.x) |
| `/var/log/suricata/fast.log` | Log des alertes Suricata (surveillé par le guard) |
| `/var/log/suricata_guard.log` | Log du script Python |
| `/var/log/suricata_blocked.log` | Log des IPs bloquées avec horodatage |
| `/var/log/suricata_guard_service.log` | Log du service systemd |
| `/var/log/fail2ban.log` | Log de Fail2ban |
| `/opt/suricata-guard/suricata_guard.py` | Script Python principal |
| `/etc/fail2ban/filter.d/portscan.conf` | Filtre Fail2ban pour les scans |
| `/etc/fail2ban/jail.d/portscan.conf` | Jail Fail2ban dédiée |
| `/proc/net/xt_recent/PORTSCAN` | Liste iptables des IPs scannantes |
| `/proc/net/xt_recent/SLOWSCAN` | Liste iptables des scans lents |
| `/proc/net/xt_recent/SSH_BRUTE` | Liste iptables des brute-force SSH |

---

## 📊 Types de détection couverts

| Menace | Détectée par | Méthode |
|---|---|---|
| Scan SYN rapide `nmap -sS -T4` | iptables + Suricata | 5 SYN en 5 secondes |
| Scan SYN lent `nmap -sS -T1` | iptables + Suricata | 20 SYN en 300 secondes |
| Scan NULL `nmap -sN` | iptables + Suricata | Aucun flag TCP |
| Scan XMAS `nmap -sX` | iptables + Suricata | FIN+PSH+URG |
| Scan FIN `nmap -sF` | iptables + Suricata | Flag FIN seul |
| Scan UDP `nmap -sU` | iptables + Suricata | Ports UDP courants |
| SYN+RST / SYN+FIN invalides | iptables | Combinaisons interdites |
| Metasploit port 4444 | Suricata | Connexion TCP/UDP port 4444 |
| SSH Brute-force | iptables + Fail2ban + Suricata | Connexions répétées port 22 |
| RDP / FTP Brute-force | Suricata | Connexions répétées |
| Ping / ICMP echo-request | Suricata | Détection simple (silencieux) |
| Ping Sweep `nmap -sn` | Suricata | 5 ICMP en 2 secondes |
| Ping of Death | Suricata | Paquet ICMP > 1000 bytes |
| Traceroute ICMP | Suricata | TTL expired répétés |
| ICMP Flood | iptables + Suricata | Plus de 10 echo-request/s |
| SYN Flood | iptables + Suricata | Plus de 50 SYN/s |
| UDP Flood | iptables + Suricata | Plus de 100 paquets UDP/s |
| DNS Amplification | Suricata | Volume UDP port 53 anormal |
| Slowloris | Suricata | Connexions HTTP lentes |
| SQLi / XSS / Webshell | Suricata | Patterns dans URI HTTP |
| SMB Scan (EternalBlue-like) | Suricata | Connexions ports 139/445 |

---

## Auteur

**12ak_H4ck** — Suricata Guard
