# 🛡️ LythorixAntiVpn

[License: GPL v3](https://www.gnu.org/licenses/gpl-3.0)
[Node.js](https://nodejs.org/)
[TypeScript](https://www.typescriptlang.org/)
[DDNet](https://ddnet.org/)

**DDNet Anti-Abuse Security System** — a powerful anti-VPN bot for DDNet/DDRace servers with advanced VPN, proxy, TOR, and datacenter detection.

---

## ✨ Features

- 🔍 **17 detection methods** for VPN/Proxy/TOR/Hosting
- 🧠 **Behavioral analysis** of players (GeoJump, IP changes, bot patterns)
- 📋 **Auto-updating blacklists** from 10+ sources (X4BNet, ScavengeR, TOR Exit Nodes)
- 🚫 **Auto-ban** mode or warning-only mode
- 📊 **Discord Webhook** notifications with detailed embeds
- ⚡ **IP caching** (24 hours TTL)
- 🔄 **Auto-reconnect** on connection loss
- 📝 **Whitelist/Blacklist** with CIDR support
- 🏢 **Anti-false-positive**: detects local ISPs, telecom providers, city networks

---

## 📋 Requirements

- **Node.js** v18 or higher
- **npm** (included with Node.js)
- **DDNet server** with RCON enabled
- **Discord Webhook** for notifications

---
```
## 🚀 Installation

### Windows

#### Step 1: Install Node.js

1. Download Node.js from [nodejs.org](https://nodejs.org/)
2. Choose the **LTS version** (18.x or higher)
3. Run the installer and follow the setup wizard
4. **Important:** Check the box "Automatically install the necessary tools" during installation
5. Verify installation — open **Command Prompt** or **PowerShell**:

powershell
node --version
npm --version
You should see version numbers (e.g., v20.11.0 and 10.2.4).

Step 2: Clone the repository
Open Command Prompt or PowerShell:

powershell
git clone https://github.com/Lythorix/AntiVpn.git
cd AntiVpn
If you don't have Git installed, download it from git-scm.com or download the repository as ZIP from GitHub.

Step 3: Install dependencies
powershell
npm install
Step 4: Configure the bot
Open config.json in any text editor (Notepad, VS Code, etc.):

json
{
  "server": {
    "host": "127.0.0.1",
    "port": 8303,
    "rcon_password": "your_rcon_password",
    "rcon_username": "your_rcon_username"
  },
  "discord": {
    "webhook_url": "https://discord.com/api/webhooks/...",
    "alert_webhook_url": "https://discord.com/api/webhooks/..."
  },
  "bot": {
    "nickname": "LythorixAntiVpn",
    "clan": "Security"
  },
  "auto_ban": {
    "enabled": false,
    "mode": "warn",
    "ban_duration_minutes": 10
  }
}
Step 5: Build TypeScript
powershell
npm run build
Step 6: Run the bot
powershell
npm start
To stop the bot, press Ctrl + C in the terminal.

Linux
Step 1: Install Node.js
Ubuntu/Debian:

bash
# Add NodeSource repository
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -

# Install Node.js and npm
sudo apt-get install -y nodejs

# Verify installation
node --version
npm --version
CentOS/RHEL/Fedora:

bash
# Add NodeSource repository
curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -

# Install Node.js and npm
sudo yum install -y nodejs

# Verify installation
node --version
npm --version
Arch Linux:

bash
sudo pacman -S nodejs npm
Step 2: Install Git (if not installed)
bash
# Ubuntu/Debian
sudo apt-get install -y git

# CentOS/RHEL
sudo yum install -y git

# Arch
sudo pacman -S git
Step 3: Clone the repository
bash
git clone https://github.com/Lythorix/AntiVpn.git
cd AntiVpn
Step 4: Install dependencies
bash
npm install
Step 5: Configure the bot
Edit config.json with nano, vim, or any text editor:

bash
nano config.json
json
{
  "server": {
    "host": "127.0.0.1",
    "port": 8303,
    "rcon_password": "your_rcon_password",
    "rcon_username": "your_rcon_username"
  },
  "discord": {
    "webhook_url": "https://discord.com/api/webhooks/...",
    "alert_webhook_url": "https://discord.com/api/webhooks/..."
  },
  "bot": {
    "nickname": "LythorixAntiVpn",
    "clan": "Security"
  },
  "auto_ban": {
    "enabled": false,
    "mode": "warn",
    "ban_duration_minutes": 10
  }
}
Save and exit (Ctrl + X, then Y, then Enter in nano).

Step 6: Build TypeScript
bash
npm run build
Step 7: Run the bot
Foreground (for testing):

bash
npm start
Press Ctrl + C to stop.

Background with screen (recommended for production):

bash
# Install screen if not installed
sudo apt-get install -y screen

# Create a new screen session
screen -S antivpn

# Start the bot
npm start

# Detach from screen: Ctrl + A, then D
# Reattach: screen -r antivpn
Background with PM2 (advanced):

bash
# Install PM2 globally
sudo npm install -g pm2

# Start the bot with PM2
pm2 start dist/index.js --name "lythorix-antivpn"

# Auto-start on system boot
pm2 startup
pm2 save

# View logs
pm2 logs lythorix-antivpn

# Stop the bot
pm2 stop lythorix-antivpn

# Restart the bot
pm2 restart lythorix-antivpn
Background with systemd (for servers):

Create a service file:

bash
sudo nano /etc/systemd/system/lythorix-antivpn.service
Paste the following:

ini
[Unit]
Description=Lythorix Anti-VPN Bot
After=network.target

[Service]
Type=simple
User=your_username
WorkingDirectory=/home/your_username/AntiVpn
ExecStart=/usr/bin/node dist/index.js
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
Then enable and start:

bash
sudo systemctl daemon-reload
sudo systemctl enable lythorix-antivpn
sudo systemctl start lythorix-antivpn

# Check status
sudo systemctl status lythorix-antivpn

# View logs
sudo journalctl -u lythorix-antivpn -f
⚙️ Configuration
auto_ban modes
Mode	Description
warn	Discord notifications only, no ban
autoban	Automatic ban when VPN/proxy detected
auto_ban.enabled
true — auto-ban enabled

false — auto-ban disabled
```
Interval settings
Parameter	Default	Description
monitoring.status_interval_seconds	40	Status check interval
ipcheck.cache_ttl_hours	24	IP cache time-to-live
ipcheck.rate_limit_ms	1500	Delay between API requests

🔧 Commands
Command	Description
npm install	Install dependencies
npm run build	Build TypeScript to JavaScript
npm start	Start the bot
npm run dev	Start in development mode
🛡️ How It Works
Bot connects to the DDNet server via RCON

Every N seconds it requests the player list (status)

For each player, it checks the IP through 5+ APIs and 12 additional methods

Analyzes ISP, organization, reverse DNS, open ports, TTL, BGP, WHOIS

When VPN/proxy detected:

Warn mode: sends Discord notification

AutoBan mode: automatically bans the player

Maintains blacklist/whitelist with auto-updates every 6 hours

🤝 Credits
Author: [Lythorix](https://github.com/Lythorix)

Libraries used:

[teeworlds](https://www.npmjs.com/package/teeworlds) — DDNet client library

[axios](https://axios.rest/) — HTTP client

[winston](https://github.com/winstonjs/winston) — Logging

[TypeScript](https://www.typescriptlang.org/) — Programming language

📄 License
This project is licensed under the GNU General Public License v3.0 — see the LICENSE file for details.

What this means:

✅ You may use, modify, and distribute this software

✅ You must open source any derivative works

❌ You may not create closed-source (proprietary) versions

⚠️ Disclaimer
This bot is designed to protect servers from abuse. The author is not responsible for false positives or any damage caused by the use of this software.

If you believe your IP has been blocked by mistake — contact the server administrator.

🌟 Support
GitHub Issues: [Report a bug](https://github.com/Lythorix/AntiVpn/issues)

Contact: [@LythorixContactBot](https://t.me/LythorixContactBot) (Telegram)
