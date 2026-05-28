# 🛡️ Lythorix Anti-VPN Manager

**DDNet Anti-Abuse Security System v2.0.0**

Protect your DDNet servers from VPN, Proxy, TOR, and hosting users with **17 detection methods** and **8000+ provider signatures**.

---

## 📥 Download

Go to [Releases](https://github.com/lythorix/antivpn/releases) and download:

| Platform | File |
|----------|------|
| 🪟 **Windows** | `LythorixAnti-VpnManager-Setup.exe` |
| 🐧 **Linux** | `LythorixAnti-VpnManager.AppImage` |

---

## 🪟 Windows

1. Download `LythorixAnti-VpnManager-Setup.exe`
2. Double-click to install
3. Launch from Desktop or Start Menu

---

## 🐧 Linux

```bash
# Download LythorixAnti-VpnManager.AppImage

# Make executable
chmod +x LythorixAnti-VpnManager.AppImage

# Run
./LythorixAnti-VpnManager.AppImage

# Optional: Install to system
mkdir -p ~/.local/bin
mv LythorixAnti-VpnManager.AppImage ~/.local/bin/lythorix-antivpn
chmod +x ~/.local/bin/lythorix-antivpn
lythorix-antivpn


Works on: Ubuntu, Fedora, Arch, Debian, Mint, Manjaro, openSUSE, Kali, Pop!_OS, Elementary, Zorin and more.

---

⚙️ Setup

Step 1: Open Editor

Click ✎ EDIT on the bot card.

Step 2: Fill Server Details

Field Description Required Example
Server Host Server IP address ✅ 87.120.186.242
Port Server port ✅ 8303
RCON Password RCON password ✅ your_password
Bot Nickname Name on server ✅ LythorixAntiVpn
Clan Clan tag ❌ Security
Discord Webhook Alert notifications ❌ https://discord.com/api/webhooks/...

Step 3: Start Bot

Click ▶ START

---

🎯 Features

Detection Engine

· 17 VPN/Proxy/TOR detection methods
· 2000+ VPN provider signatures
· 1000+ Datacenter providers
· 1000+ Proxy services
· 4000+ Trusted ISPs (no false bans)

Bot Management

· 🤖 Multiple bots simultaneously
· 📋 Duplicate bots with one click
· ⚡ Real-time colored console
· 💾 Auto-save configuration
· 📱 System tray background mode

Security

· 🔐 AES-256-GCM encrypted source code
· 🛡️ Memory protection (anti-debug)
· 🔒 VM-isolated execution

---

📖 Usage

Modes

Click mode indicator to switch:

Mode Behavior
🔨 AUTOBAN Auto-ban VPN users
⚠️ WARN ONLY Send warnings only
🔴 DISABLED No action

IP Lists

· Whitelist: Trusted IPs (never checked)
· Blacklist: Always banned IPs
· 🔍 Search: Find IP across lists
· 📋 Copy: Copy IP to clipboard

Background Mode

· Close window → bot keeps running
· System tray icon shows status
· Double-click tray → restore window

---

❓ FAQ

Connection

Q: Bot won't connect to server?
A: Check that:

· Server IP and port are correct
· RCON password is valid
· Server is online
· Firewall is not blocking

Q: Bot connects but disconnects immediately?
A: The server may have sv_rcon_max_tries limit. Try increasing it or check RCON credentials.

Q: Can I run multiple bots?
A: Yes. Click 📋 DUPLICATE and configure different servers. Each bot runs independently.

Detection

Q: Will it ban real players by mistake?
A: No. The bot checks against 4000+ trusted ISPs (Kyivstar, Vodafone, Deutsche Telekom, AT&T, etc.) before banning.

Q: What if a legitimate player uses VPN for work?
A: Add their IP to the Whitelist. Whitelisted IPs are never checked.

Q: How accurate is the detection?
A: Very accurate. Uses 17 different methods including API checks, reverse DNS, TTL analysis, JA3 fingerprinting, and behavioral analysis. ~1-4 seconds

Q: Does it detect TOR exit nodes?
A: Yes. TOR nodes are automatically detected and blocked.

Configuration

Q: How do I change ban duration?
A: In EDIT panel, change Ban Duration field and click 💾 SAVE.

Q: How do I switch from AutoBan to Warn mode?
A: Click the mode indicator (green/yellow bar) in the editor. It toggles between modes.

Q: Can I customize the ban message?
A: Yes. Edit Ban Reason and Contact fields in EDIT panel.

Q: Where are settings stored?
A:

· Windows: %APPDATA%\ddnet-antivpn-manager\
· Linux: ~/.config/ddnet-antivpn-manager/

Discord

Q: How do I set up Discord alerts?
A:

1. Create a webhook in your Discord server
2. Paste URL into Discord Webhook field
3. Bot will send alerts when VPN users are detected

Q: What's the difference between Webhook and Alert Webhook?
A:

· Webhook: All events (connections, detections, bans)
· Alert Webhook: Critical alerts only (VPN detected, banned)

Troubleshooting

Q: White screen when starting?
A: Reinstall or download the latest version from Releases.

Q: Bot stopped working after update?
A: Delete config folder and reconfigure:

· Windows: rmdir /s /q "%APPDATA%\ddnet-antivpn-manager"
· Linux: rm -rf ~/.config/ddnet-antivpn-manager

Q: High CPU usage?
A: Normal on first run (loading IP lists). Should stabilize after 1-2 minutes.

Q: Bot uses too much RAM?
A: The bot caches IP checks. Clear cache by deleting checked_ips.json in the data folder.

Q: Linux AppImage won't run?

```bash
# Install FUSE if missing
sudo apt install fuse libfuse2   # Debian/Ubuntu
sudo dnf install fuse             # Fedora
sudo pacman -S fuse2              # Arch
```

Q: Where are logs stored?
A: In the bot's data folder:

· Windows: %APPDATA%\ddnet-antivpn-manager\bots\[id]\logs\
· Linux: ~/.config/ddnet-antivpn-manager/bots/[id]/logs/

---

🏆 Credits

Developer

· [Lythorix](https://github.com/Lythorix/) - Creator
· [DeepSeek](https://chat.deepseek.com/) - Main developer
· [Swarfey](https://github.com/Swarfeya) - Library developer

Bot Engine

· [Teeworlds](https://www.npmjs.com/package/teeworlds) - Bot library

Detection APIs

· ip-api.com - Geolocation data
· ipwhois.io - VPN/Proxy detection
· ipapi.co - ASN & hosting data
· freeipapi.com - VPN/TOR/Proxy flags
· ipinfo.io - Privacy detection

Provider Lists

· X4BNet/lists_vpn - VPN IP lists
· Scav-engeR/vpn_list - VPN IP lists
· TheSpeedX/SOCKS-List - Proxy lists
· Tor Project - TOR exit nodes

Design

· Custom Black-Mint theme
· System tray integration
· Real-time console output

---

📞 Contact

· Telegram: @LythorixContactBot
· GitHub: [Report Issue](https://github.com/Lythorix/AntiVpn/issues)


```
