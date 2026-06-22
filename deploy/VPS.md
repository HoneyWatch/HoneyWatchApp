# HoneyWatch — dashboard na VPS (dane na żywo)

Dashboard czyta **bezpośrednio** `/opt/honeywatch/honeywatch.db` na serwerze. Parser (`parser.py` + cron) dopisuje ataki do bazy co minutę — strona odświeża wykresy po F5 lub przycisku Refresh (bez ręcznego `scp`).

## Co musi już działać na VPS

- Cowrie + parser zapisujący do `/opt/honeywatch/honeywatch.db`
- SSH na porcie **2223** (jak u Ciebie): `root@91.228.196.200`

## Krok 1 — skopiuj projekt z Windows na VPS

W PowerShell (z folderu projektu):

```powershell
cd C:\Users\mateu\Desktop\HoneyWatchApp

# Utwórz katalog na VPS
ssh -p 2223 root@91.228.196.200 "mkdir -p /opt/honeywatch/HoneyWatchApp"

# Skopiuj dashboard + deploy + requirements (bez __pycache__)
scp -P 2223 -r dashboard requirements.txt deploy root@91.228.196.200:/opt/honeywatch/HoneyWatchApp/
```

Alternatywa: `git clone` repozytorium do `/opt/honeywatch/HoneyWatchApp`.

## Krok 2 — instalacja na VPS

Zaloguj się:

```bash
ssh -p 2223 root@91.228.196.200
```

Uruchom skrypt instalacyjny:

```bash
bash /opt/honeywatch/HoneyWatchApp/deploy/install-vps.sh
```

To tworzy venv w `/opt/honeywatch/venv`, instaluje Flask i uruchamia usługę **systemd** `honeywatch-dashboard`.

## Krok 3 — firewall (ważne)

**Nie** otwieraj portu 5000 dla całego internetu — w bazie są IP i hasła z honeypota.

Tylko Twoje IP (podmień `TWOJE_IP`):

```bash
ufw allow 2223/tcp
ufw allow from TWOJE_IP to any port 5000 proto tcp
ufw enable
ufw status
```

## Krok 4 — sprawdzenie

Na VPS:

```bash
systemctl status honeywatch-dashboard
curl -s http://127.0.0.1:5000/api/summary
```

W przeglądarce na PC:

- **http://91.228.196.200:5000/** — cały dashboard (mapa, wykresy)
- **http://91.228.196.200:5000/api/summary** — JSON (test API)

Powinno pokazywać realne liczby z bazy (nie mock 15892).

## Parser (bez duplikatów)

Parser w `deploy/parser.py` czyta logi **tylko od ostatniej pozycji** (`parser_state`) i pomija **identyczne** wpisy (`INSERT OR IGNORE` + indeks UNIQUE). Ten sam IP może atakować wiele razy — odrzucane są tylko pełne duplikaty z ponownego parsowania.

Wgranie na VPS (np. do `/opt/honeywatch/parser.py`):

```powershell
scp -P 2223 deploy/parser.py root@91.228.196.200:/opt/honeywatch/parser.py
```

Pierwsze uruchomienie po aktualizacji usuwa stare duplikaty i zakłada indeksy:

```bash
python3 /opt/honeywatch/parser.py
```

**Uwaga:** przy pierwszym uruchomieniu nowego parsera offset startuje od końca pliku (nie reimportuje całej historii). Aby przejść od początku logu: `DELETE FROM parser_state;` i uruchom parser ponownie (wtedy dedup i tak zablokuje identyczne linie).

## Aktualizacja po zmianach w kodzie

Z Windows:

```powershell
scp -P 2223 -r dashboard root@91.228.196.200:/opt/honeywatch/HoneyWatchApp/
ssh -p 2223 root@91.228.196.200 "systemctl restart honeywatch-dashboard"
```

## Przydatne komendy

| Akcja | Komenda |
|--------|---------|
| Logi | `journalctl -u honeywatch-dashboard -f` |
| Restart | `systemctl restart honeywatch-dashboard` |
| Stop | `systemctl stop honeywatch-dashboard` |
| Ścieżka bazy | `HONEYWATCH_DB=/opt/honeywatch/honeywatch.db` (już w systemd) |

## Opcjonalnie: HTTPS + domena (później)

Dla projektu wystarczy HTTP + port 5000 z ograniczeniem IP. Na produkcję: nginx + Let's Encrypt na porcie 443.

## Lokalny dev vs VPS

| | Lokalnie (PC) | VPS |
|--|----------------|-----|
| Baza | `Desktop\honeywatch.db` (scp) | `/opt/honeywatch/honeywatch.db` (na żywo) |
| Uruchomienie | `python -m dashboard.app` | `systemctl start honeywatch-dashboard` |
| Dane | Po każdym scp | Automatycznie z parsera |

Nie musisz już uruchamiać osobnego `api.py` z wiki — ten dashboard ma wszystkie endpointy (`/api/geo`, `/api/timeline`, …).
