# Deploying on a home server (ZimaBlade / ZimaOS)

The whole stack runs in Docker on a single x86 box. Reference hardware:
ZimaBlade (Intel Celeron J3455, 8–16 GB RAM, SATA SSD for data).

## Layout

```
/DATA/AppData/ukphish/        project root (on the SATA disk, not the eMMC)
├── config/                   brands and scoring weights (mounted read-only)
├── data/detections.db        SQLite database (owned by uid 1000)
├── .env                      secrets (never committed)
└── docker-compose.yml
```

## Deploy

```bash
ssh <user>@<zimablade-ip>
mkdir -p /DATA/AppData && cd /DATA/AppData
git clone https://github.com/<you>/uk-bank-phish-monitor.git ukphish
cd ukphish
cp .env.example .env
mkdir -p data && sudo chown 1000:1000 data
docker compose up -d --build
docker compose ps
```

Then open `http://<zimablade-ip>:5678`, import `n8n/ukphish_workflow.json`,
configure the Telegram node and activate the workflow.

## Operations

| Task | Command |
|---|---|
| Live logs | `docker compose logs -f collector` |
| Resource usage | `docker stats` |
| Top detections | `docker compose exec collector ukphish top --limit 20` |
| Stats per brand | `docker compose exec collector ukphish stats` |
| Run dnstwist now | `docker compose exec dnstwist ukphish dnstwist` |
| Update code | `git pull && docker compose up -d --build` |
| Change brands/weights | edit `config/*.yaml`, then `docker compose restart collector dnstwist` |

## Backups

```bash
sqlite3 data/detections.db ".backup 'backup-$(date +%F).db'"
docker run --rm -v ukphish_n8n_data:/src -v "$PWD":/dst alpine \
  tar czf /dst/n8n-backup-$(date +%F).tgz -C /src .
```

## Security

- Only port 5678 (n8n UI) is published, and it must stay on the LAN.
  For remote access use a VPN such as Tailscale or WireGuard, never port
  forwarding on the router.
- certstream and the n8n webhook are reachable only inside the Docker network.
- All traffic leaving the box is outbound (CT stream, RDAP, DNS, Telegram API).
