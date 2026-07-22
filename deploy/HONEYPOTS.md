# HoneyWatch — instalacja i konfiguracja honeypotów (VPS)

Kompletny runbook: **Cowrie** (SSH/Telnet), **OpenCanary** (multi-serwis) i **Dionaea** (SMB + malware) na jednym VPS, plus **parser** zbierający logi do SQLite i **dashboard** Flask.

> Wartości specyficzne dla tego wdrożenia (podmień pod siebie):
> - VPS: `91.228.196.200`, admin SSH na porcie **2223**
> - Katalog aplikacji: `/opt/honeywatch`
> - Baza: `/opt/honeywatch/honeywatch.db`

## Spis treści

1. [Architektura i podział portów](#1-architektura-i-podział-portów)
2. [Przygotowanie serwera](#2-przygotowanie-serwera)
3. [Cowrie (SSH/Telnet)](#3-cowrie-sshtelnet)
4. [OpenCanary (FTP/HTTP/DB/RDP/...)](#4-opencanary)
5. [Dionaea (SMB + malware, Docker)](#5-dionaea-docker)
6. [Parser (logi → SQLite)](#6-parser-logi--sqlite)
7. [Dashboard (Flask)](#7-dashboard-flask)
8. [Firewall (ufw)](#8-firewall-ufw)
9. [Weryfikacja end-to-end](#9-weryfikacja-end-to-end)
10. [Troubleshooting (realne pułapki)](#10-troubleshooting-realne-pułapki)

---

## 1. Architektura i podział portów

```
Internet → porty honeypotów → logi → parser (cron) → honeywatch.db → dashboard
```

| Honeypot | Technologia | Porty (na świat) | Log |
|----------|-------------|------------------|-----|
| Cowrie | natywnie (venv), user `cowrie` | 22, 23 → REDIRECT 2222 | `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` |
| OpenCanary | natywnie (`twistd`) | 21, 80, 1433, 3306, 3389, 5060/udp, 5900, 9418 | `/var/log/opencanary.log` |
| Dionaea | Docker `dinotools/dionaea` | 445 (opcjonalnie 135, 69/udp, 1883, 11211, 27017) | `/opt/honeywatch/dionaea/lib/dionaea.json` |

**Zasada:** każdy port obsługuje tylko jeden honeypot. Admin SSH przenieś na **2223**, żeby port 22 mógł trafiać do Cowrie.

---

## 2. Przygotowanie serwera

```bash
# jako root
apt-get update && apt-get -y upgrade

# przenieś administracyjny SSH na 2223 (żeby 22 było wolne dla Cowrie)
sed -i 's/^#\?Port .*/Port 2223/' /etc/ssh/sshd_config
systemctl restart ssh
# UWAGA: zaloguj się nową sesją na 2223 ZANIM zamkniesz obecną!

mkdir -p /opt/honeywatch
```

---

## 3. Cowrie (SSH/Telnet)

### 3.1 Zależności i użytkownik

```bash
apt-get install -y git python3-venv python3-pip python3-dev \
  libssl-dev libffi-dev build-essential authbind

adduser --disabled-password --gecos "" cowrie
```

### 3.2 Instalacja (jako user cowrie)

```bash
su - cowrie
git clone https://github.com/cowrie/cowrie /home/cowrie/cowrie
cd /home/cowrie/cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3.3 Konfiguracja — logi JSON

```bash
cp etc/cowrie.cfg.dist etc/cowrie.cfg
```

W `etc/cowrie.cfg` upewnij się, że wyjście JSON jest włączone (parser czyta właśnie ten plik):

```ini
[output_jsonlog]
enabled = true
logfile = ${honeypot:log_path}/cowrie.json
```

Cowrie domyślnie słucha na **2222** (SSH) i **2223** wewnętrznie dla telnet — u nas telnet też mapujemy na 2222; sprawdź sekcję `[ssh]`/`[telnet]`. Wyjdź z konta cowrie: `exit`.

### 3.4 Przekierowanie 22/23 → 2222 (iptables)

```bash
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 2222
iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-ports 2222

# zapisz na stałe (przetrwa reboot)
apt-get install -y iptables-persistent
netfilter-persistent save
```

### 3.5 Usługa systemd

Utwórz `/etc/systemd/system/cowrie.service`:

```ini
[Unit]
Description=Cowrie SSH/Telnet Honeypot
After=network.target

[Service]
Type=simple
User=cowrie
Group=cowrie
WorkingDirectory=/home/cowrie/cowrie
# WAŻNE: usuwa zostawiony pidfile po nagłym reboocie (patrz Troubleshooting)
ExecStartPre=/bin/rm -f /home/cowrie/cowrie/twistd.pid
ExecStart=/home/cowrie/cowrie/cowrie-env/bin/twistd -n --logger cowrie.python.logfile.logger cowrie
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now cowrie
systemctl status cowrie --no-pager | head -6
ss -tlnp | grep 2222        # powinien nasłuchiwać twistd
```

---

## 4. OpenCanary

### 4.1 Instalacja

```bash
apt-get install -y python3-dev python3-pip python3-venv python3-scapy libpcap-dev

python3 -m venv /opt/opencanary/env
/opt/opencanary/env/bin/pip install --upgrade pip
/opt/opencanary/env/bin/pip install opencanary
# dla emulacji Windows/SMB share (opcjonalnie): apt-get install -y samba
```

### 4.2 Konfiguracja usług i portów

```bash
/opt/opencanary/env/bin/opencanaryd --copyconfig
# tworzy ~/.opencanary.conf — u nas config trzymamy w /etc/opencanaryd/opencanary.conf
mkdir -p /etc/opencanaryd
cp ~/.opencanary.conf /etc/opencanaryd/opencanary.conf
```

W `/etc/opencanaryd/opencanary.conf` włącz usługi (`"<svc>.enabled": true`) i ustaw porty. U nas aktywne:

| Usługa | Port |
|--------|------|
| ftp | 21 |
| http | 80 |
| mssql | 1433 |
| mysql | 3306 |
| rdp | 3389 |
| sip | 5060/udp |
| vnc | 5900 |
| git | 9418 |

Logi kieruj do pliku:

```json
"logger": {
  "class": "PyLogger",
  "kwargs": {
    "handlers": {
      "file": { "class": "logging.FileHandler", "filename": "/var/log/opencanary.log" }
    }
  }
}
```

### 4.3 Usługa systemd

Utwórz `/etc/systemd/system/opencanary.service`:

```ini
[Unit]
Description=OpenCanary Honeypot
After=network.target

[Service]
Type=simple
ExecStart=/opt/opencanary/env/bin/opencanaryd --dev
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now opencanary
ss -tulnp | grep twistd     # powinny być porty z tabeli wyżej
```

---

## 5. Dionaea (Docker)

Dionaea to główny „łapacz" SMB (445) i malware. Uruchamiamy z obrazu `dinotools/dionaea`.

### 5.1 Docker + katalog na dane (z poprawnymi uprawnieniami!)

```bash
apt-get install -y docker.io
systemctl enable --now docker
docker pull dinotools/dionaea

# katalog na stan/logi Dionaei, montowany do kontenera
mkdir -p /opt/honeywatch/dionaea/lib
# WAŻNE: proces dionaea w kontenerze pisze jako uid 1000 — bez tego nie zapisze NICZEGO
chown -R 1000:1000 /opt/honeywatch/dionaea/lib
```

### 5.2 Uruchomienie kontenera

Minimalnie (samo SMB):

```bash
docker run -d --name dionaea --restart unless-stopped \
  -p 445:445 \
  -v /opt/honeywatch/dionaea/lib:/opt/dionaea/var/lib/dionaea \
  dinotools/dionaea
```

Rozszerzony zestaw portów (usługi, których NIE ma OpenCanary — bez kolizji):

```bash
docker run -d --name dionaea --restart unless-stopped \
  -p 445:445 \
  -p 135:135 \
  -p 1883:1883 \
  -p 11211:11211 \
  -p 27017:27017 \
  -p 69:69/udp \
  -v /opt/honeywatch/dionaea/lib:/opt/dionaea/var/lib/dionaea \
  dinotools/dionaea
```

| Port | Usługa | Uwaga |
|------|--------|-------|
| 445 | SMB | flagowy (EternalBlue itp.) |
| 135 | MS-RPC / epmap | cel robaków |
| 69/udp | TFTP | transfer plików |
| 1883 | MQTT | IoT |
| 11211 | memcache | amplifikacja |
| 27017 | MongoDB | ataki na NoSQL |

### 5.3 Włączenie logu JSON (`log_json`)

Obraz domyślnie **nie** ma włączonego `log_json`, więc `dionaea.json` nie powstaje. Włącz go w kontenerze:

```bash
docker exec dionaea sh -c 'printf "%s\n" \
  "- name: log_json" \
  "  config:" \
  "    handlers:" \
  "      - file:///opt/dionaea/var/lib/dionaea/dionaea.json" \
  > /opt/dionaea/etc/dionaea/ihandlers-enabled/log_json.yaml'

docker restart dionaea
```

> Uwaga: ten plik żyje **wewnątrz** kontenera. Po `docker rm` (np. przy zmianie portów) trzeba go dodać ponownie.

### 5.4 Test zapisu

```bash
# wymuś połączenie na SMB i sprawdź, czy pojawia się JSON
timeout 2 bash -c 'cat < /dev/null > /dev/tcp/127.0.0.1/445'; sleep 2
tail -n 3 /opt/honeywatch/dionaea/lib/dionaea.json
```

Plik `dionaea.json` (i `dionaea.sqlite`) powinny się pojawić w `/opt/honeywatch/dionaea/lib/`.

---

## 6. Parser (logi → SQLite)

Parser (`/opt/honeywatch/parser.py`) czyta trzy logi i dopisuje nowe zdarzenia do bazy. Kluczowe ścieżki na górze pliku:

```python
DB_PATH        = "/opt/honeywatch/honeywatch.db"
COWRIE_LOG     = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
OPENCANARY_LOG = "/var/log/opencanary.log"
DIONAEA_LOG    = os.environ.get("DIONAEA_LOG", "/var/lib/dionaea/dionaea.json")
```

Wgraj parser i zainicjuj bazę:

```bash
# z Windows (z katalogu projektu):
scp -P 2223 deploy/parser.py root@91.228.196.200:/opt/honeywatch/parser.py

# na VPS — pierwsze uruchomienie tworzy tabele i indeksy
DIONAEA_LOG=/opt/honeywatch/dionaea/lib/dionaea.json python3 /opt/honeywatch/parser.py
```

### 6.1 Cron (co minutę)

`crontab -e` i dodaj (uwaga na `DIONAEA_LOG` — u nas plik jest w bind-moncie, nie w domyślnej ścieżce):

```cron
* * * * * DIONAEA_LOG=/opt/honeywatch/dionaea/lib/dionaea.json /usr/bin/python3 /opt/honeywatch/parser.py
```

Sprawdź:

```bash
crontab -l | grep parser
sqlite3 /opt/honeywatch/honeywatch.db "SELECT source, COUNT(*) FROM attacks GROUP BY source;"
```

---

## 7. Dashboard (Flask)

Repo zawiera gotowy skrypt i usługę.

```bash
# skopiuj projekt na VPS
ssh -p 2223 root@91.228.196.200 "mkdir -p /opt/honeywatch/HoneyWatchApp"
scp -P 2223 -r dashboard requirements.txt deploy \
  root@91.228.196.200:/opt/honeywatch/HoneyWatchApp/

# na VPS: instalacja venv + usługa systemd honeywatch-dashboard
bash /opt/honeywatch/HoneyWatchApp/deploy/install-vps.sh
```

Usługa czyta bazę na żywo (`Environment=HONEYWATCH_DB=/opt/honeywatch/honeywatch.db`) i słucha na porcie **5000**. Szczegóły i aktualizacje: `deploy/VPS.md`.

---

## 8. Firewall (ufw)

**Nie** wystawiaj portu 5000 (dashboardu) na świat — w bazie są prawdziwe IP i przechwycone hasła.

```bash
ufw allow 2223/tcp                       # admin SSH
# porty honeypotów mają być otwarte (o to chodzi):
ufw allow 22,23,21,80,445,1433,3306,3389,5900,9418/tcp
ufw allow 5060/udp
ufw allow 69/udp

# dashboard tylko dla siebie — patrz sekcja o dostępie w VPS.md
ufw allow from TWOJE_IP to any port 5000 proto tcp
ufw enable
ufw status
```

> Docker publikuje porty własnymi regułami iptables (z pominięciem ufw) — dlatego port 445 Dionaei jest osiągalny z internetu nawet bez wpisu w ufw.

---

## 9. Weryfikacja end-to-end

```bash
# 1. wszystkie honeypoty nasłuchują
ss -tulnp | grep -E 'twistd|docker-proxy'

# 2. logi rosną
tail -n 2 /home/cowrie/cowrie/var/log/cowrie/cowrie.json
tail -n 2 /var/log/opencanary.log
tail -n 2 /opt/honeywatch/dionaea/lib/dionaea.json

# 3. parser wypełnia bazę (wszystkie 3 źródła)
sqlite3 /opt/honeywatch/honeywatch.db \
  "SELECT source, COUNT(*), MAX(timestamp) FROM attacks GROUP BY source;"

# 4. dashboard odpowiada
systemctl status honeywatch-dashboard --no-pager | head -5
curl -s http://127.0.0.1:5000/api/summary
```

---

## 10. Troubleshooting (realne pułapki)

### Cowrie pada w pętli: `Can't check status of PID ... from pidfile twistd.pid: Operation not permitted`
Zostawiony `twistd.pid` po reboocie — stary PID został przydzielony innemu procesowi, więc Cowrie myśli, że już działa.

```bash
systemctl stop cowrie
rm -f /home/cowrie/cowrie/twistd.pid
systemctl start cowrie
```

Trwałe zabezpieczenie: `ExecStartPre=/bin/rm -f /home/cowrie/cowrie/twistd.pid` w usłudze (jest już w sekcji 3.5).

### Dionaea nie tworzy `dionaea.json` ani `dionaea.sqlite` (katalog pusty)
Bind-mount należy do `root`, a proces dionaea pisze jako uid **1000** → brak uprawnień (`unable to open database file` w `docker logs dionaea`).

```bash
docker exec dionaea id -u dionaea        # zwykle 1000
chown -R 1000:1000 /opt/honeywatch/dionaea/lib
docker restart dionaea
```

### Parser: `Brak pliku: /var/lib/dionaea/dionaea.json`
Zła ścieżka — u nas log jest w bind-moncie. Ustaw `DIONAEA_LOG`:

```bash
DIONAEA_LOG=/opt/honeywatch/dionaea/lib/dionaea.json python3 /opt/honeywatch/parser.py
```

i dopisz tę zmienną do wpisu w cronie (sekcja 6.1).

### Dionaea łapie tylko SMB
Kontener ma opublikowany tylko port 445. Dodaj kolejne porty — trzeba **odtworzyć** kontener (`docker rm` + `docker run` z sekcji 5.2), a potem ponownie włączyć `log_json` (sekcja 5.3).

### Dashboard pokazuje „No logs in this time range"
Dane są, ale poza wybranym oknem czasowym (np. honeypot był chwilę wyłączony). Ustaw zakres „30 dni" albo sprawdź `MAX(timestamp)` per źródło (sekcja 9, pkt 3).

### Wszystkie `src_ip` Dionaei to `172.17.0.1`
Połączenia idą przez `docker-proxy` (np. testy z samego hosta) i tracą źródłowy adres. Dla ruchu z internetu Docker zwykle zachowuje realne IP. Jeśli jednak wszystkie są zmaskowane — ustaw `"userland-proxy": false` w `/etc/docker/daemon.json` i `systemctl restart docker`.
