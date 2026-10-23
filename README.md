<div align="center">

<img src="screenshots/logo.png" width="96" alt="NetWarden logo">

# NetWarden

**A lightweight, NetLimiter-style bandwidth monitor, limiter and app firewall for Windows 11.**

See which apps use your internet, cap their speed, or block them — from a single ~260 KB portable EXE.

[![Download](https://img.shields.io/github/v/release/hansonds/NetWarden?label=Download&style=for-the-badge&color=3B7BFF)](https://github.com/hansonds/NetWarden/releases/latest)
[![Build](https://img.shields.io/github/actions/workflow/status/hansonds/NetWarden/build.yml?style=for-the-badge&label=Build)](https://github.com/hansonds/NetWarden/actions/workflows/build.yml)
![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4?style=for-the-badge&logo=windows)
![Size](https://img.shields.io/badge/size-~260%20KB-35D49A?style=for-the-badge)
![Portable](https://img.shields.io/badge/install-not%20needed-FF8B3D?style=for-the-badge)

**[⬇️ Download](https://github.com/hansonds/NetWarden/releases/latest)** · [Features](#-features) · [Screenshots](#-screenshots) · [How to use](#-how-to-use) · [FAQ](#-faq) · [Changelog](#-changelog)

<img src="screenshots/main.png" alt="NetWarden main window" width="900">

</div>

---

## ✨ Features

| | |
|---|---|
| 📊 **Live per-app traffic** | Download / upload speed, session totals and open connections for every program, with activity bars and a 2-minute traffic graph. |
| 🐢 **Per-app speed limits** | Cap the download and/or upload speed of any app. Limits are smooth and accurate (within ~2%) because traffic is *delayed*, not just dropped. |
| 📏 **Any unit you like** | B/s, KB/s, MB/s, GB/s, bit/s, Kbit/s, Mbit/s, Gbit/s — default KB/s. Each rule remembers its unit. |
| ⛔ **Block apps** | Cut any program off from the internet with one click. |
| 🌐 **Global limits** | Cap the total speed of the whole PC — works together with per-app limits. |
| 📶 **Mobile Hotspot aware** | Traffic used by phones/PCs connected to your Windows Mobile Hotspot shows up as its own entry — and can be limited or blocked too. |
| 🔌 **Connections view** | See each app's TCP/UDP connections, remote addresses and states. |
| 💾 **Rules remembered** | Limits and blocks are saved and re-applied automatically, even for apps you start later. |
| ⏸️ **Pause all rules** | One click to turn every limit off (and back on). |
| 🖥️ **Tray & autostart** | Lives in the system tray with live speeds in the tooltip. Optional *Start with Windows* (no UAC prompt at logon). |
| 🪶 **Lightweight** | One tiny EXE, no installer, no background service. Uses the .NET Framework already built into Windows. |

---

## 📸 Screenshots

<table>
<tr>
<td width="50%"><img src="screenshots/details.png" alt="App details and rules"><br><sub><b>App details</b> — live speed, limits, block and connections</sub></td>
<td width="50%"><img src="screenshots/units.png" alt="Unit picker"><br><sub><b>Unit picker</b> — set limits in KB/s, MB/s, Mbit/s and more</sub></td>
</tr>
<tr>
<td width="50%"><img src="screenshots/menu.png" alt="Right-click menu"><br><sub><b>Right-click menu</b> — quick limit, block, open file location</sub></td>
<td width="50%"><img src="screenshots/rules.png" alt="Rules window"><br><sub><b>Rules</b> — enable, disable or delete saved rules</sub></td>
</tr>
</table>

---

## 📥 Download & run

1. Go to **[Releases](https://github.com/hansonds/NetWarden/releases/latest)** and download the latest `NetWarden-vX.X.X.zip`.
2. Extract it anywhere (e.g. `C:\Tools\NetWarden`).
3. Run **`NetWarden.exe`** and click **Yes** on the administrator prompt.

That's it — no installation. To update, close NetWarden (tray icon → **Exit**) and replace the EXE. Your rules are kept.

> **Requirements:** Windows 10 or 11, 64-bit (Intel/AMD). Administrator rights.
> ARM-based Windows PCs are not supported.

---

## 🚀 How to use

**Limit an app**
1. Click the app in the list.
2. On the right, tick **Limit download** and/or **Limit upload**.
3. Type a number and pick a unit — the limit applies instantly.

**Block an app** — tick **Block all internet access** (or right-click → *Block internet access*).

**Limit the whole PC** — click **Global limits** at the top.

**Manage rules** — the **Rules** button lists every rule; **Pause rules** turns them all off temporarily.

**Hotspot devices** — turn on Windows *Mobile Hotspot*; connected devices appear as **Mobile Hotspot** and can be limited like any app.

**Settings (☰ menu)** — Start with Windows, minimize to tray on close, show idle apps, reset counters.

> 💡 Switching units keeps the same real speed: 512 KB/s → 0.5 MB/s.
> Byte units use 1024 (1 MB/s = 1024 KB/s); bit units use 1000, like internet plans (10 Mbit/s = 1.25 MB/s).

---

## ⚙️ How it works

NetWarden uses **[WinDivert](https://github.com/basil00/WinDivert)**, a signed, open-source Windows packet driver.

- **Monitoring only** (no rules active): NetWarden just *watches a copy* of the traffic — zero added latency.
- **Limits/blocks active**: packets of the affected apps go through a token-bucket shaper that smoothly delays them to the set speed.
- Traffic is matched to apps using Windows' own connection tables, so names, icons and paths are exact.
- The driver is embedded in the EXE, loaded only while NetWarden runs, and unloaded when it exits. If NetWarden closes or crashes, your internet keeps working normally.

Settings are stored in `%AppData%\NetWarden\config.json`.

---

## ❓ FAQ

<details>
<summary><b>Why does it need administrator rights?</b></summary>

Seeing and controlling network traffic requires a kernel driver, and Windows only lets administrators load drivers.
</details>

<details>
<summary><b>My antivirus warns about WinDivert.</b></summary>

Some antivirus tools flag WinDivert as a generic "network tool" because it can intercept traffic. It's a well-known, signed open-source driver used by many projects. Add an exception if needed.
</details>

<details>
<summary><b>What is "Unknown / pending"?</b></summary>

Brand-new connections for a second or two before Windows reports which app owns them, plus a little traffic handled by drivers (e.g. some VPNs) rather than programs.
</details>

<details>
<summary><b>Where is NetWarden when I close the window?</b></summary>

It keeps running in the system tray so your limits stay active. Right-click the tray icon → **Exit** to close it completely. You can change this in ☰ → *Close button minimizes to tray*.
</details>

<details>
<summary><b>How do I remove it completely?</b></summary>

Turn off ☰ → *Start with Windows*, exit NetWarden, then delete its folder, `%AppData%\NetWarden` and `C:\ProgramData\NetWarden`. Nothing else is left on the system.
</details>

<details>
<summary><b>Does it limit traffic between apps on the same PC?</b></summary>

No — local (localhost) traffic is ignored; only real network traffic is counted and limited.
</details>

---

## 📝 Changelog

**v1.1.0**
- 📶 Mobile Hotspot traffic now appears as its own entry (instead of "Unknown") and can be limited or blocked
- Uploads from hotspot devices are now counted

**v1.0.3**
- Right-click menu fixed: limit, block/unblock, remove rule, open file location, copy path

**v1.0.2**
- Unit dropdown for every limit: B/s … GB/s and bit/s … Gbit/s (default KB/s)

**v1.0.1**
- New flicker-free app list with hover highlight, smooth scrolling and keyboard navigation

**v1.0.0**
- First release: live per-app monitoring, per-app and global speed limits, blocking, connections view, tray mode, Start with Windows

---

## 🛠️ Build from source

The app is C# (WinForms, .NET Framework 4.8) with no external dependencies.

### On GitHub (no software needed)
Go to **Actions → Build NetWarden → Run workflow**. About 2 minutes later the new zip appears on the **[Releases](https://github.com/hansonds/NetWarden/releases)** page automatically (and under *Artifacts* on the run page).

A build also runs automatically whenever files in `src/` change.

**Releasing a new version**
1. Edit `src/Program.cs` and change `Version = "1.1.0"` to the new number (e.g. `1.2.0`).
2. Commit. The workflow builds it and publishes the **v1.2.0** release by itself.

> If the release step fails, open **Settings → Actions → General → Workflow permissions**, choose **Read and write permissions**, and run the workflow again.

### On your own PC
**Windows** (Visual Studio 2022 or .NET SDK):
```
dotnet build src/NetWarden.csproj -c Release
```

**Linux** (cross-build): `build/build.sh` — uses the .NET SDK's C# compiler with Mono's .NET Framework reference assemblies.

### Project layout
```
.github/workflows/build.yml   automatic build + release
src/
├── Program.cs     startup, admin check, driver unpacking, version number
├── Engine.cs      packet capture, app matching, shaping, hotspot
├── Native.cs      WinDivert + Windows API interop
├── Config.cs      rules/settings, Start-with-Windows task
├── MainForm.cs    main window, dialogs
└── Theme.cs       dark theme, custom list, graph, unit picker
screenshots/       images used in this README
```

---

## 📄 License

NetWarden is released under the [MIT License](LICENSE).
Bundled **WinDivert 2.2.2** © basil00, licensed under LGPL v3 — see [`src/WinDivert-LICENSE.txt`](src/WinDivert-LICENSE.txt).

<div align="center"><sub>Made by <a href="https://github.com/hansonds">Hanson</a></sub></div>
