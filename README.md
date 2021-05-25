# IW4MAdmin [![GitHub license](https://img.shields.io/github/license/RaidMax/IW4M-Admin)](https://github.com/Zwambro/iw4madmin-plugin-iw4todiscord/blob/master/LICENSE) [![GitHub stars](https://img.shields.io/github/stars/RaidMax/IW4M-Admin)](https://github.com/RaidMax/IW4M-Admin/stargazers)  
[![ko-fi](https://www.ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/J3J821KUJ)


# A VPN Detector for IW4MAdmin
## Requirement
- You may need IW4MAdmin version `2021.5.15.3` or later.

## Introduction
Updated version of IW4MAdmin default plugin "VPNDetection", This updated version will help you to avoid limited requests problem by:
- Save all detected VPN IPs on Zwambro DB, to use it as antivpn provider between Gaming communities (will be always free).
- Adding the maximum level/rank affected by this plugin, if the player's rank is less than the maxLevel setting, it will checked by this plugin.
- Addition of Maximum Connections option, if the maximum player connections are less than maxConnections setting, it will be affected by this plugin.
- Added a new command to allow a VPN user, syntax : `!allowvpn playername/@playerd`.
- Added a new command to remove an allowed VPN user, syntax : `!denyvpn playername/@playerd`.

## Commands
- `!allowvpn playername/@playerd`
- `!denyvpn playername/@playerd`

## Installation
1. **Merge** this plugin with default one (take a backup of this plugin first).
2. Restart IW4MAdmin.
3. Go to [proxycheck.io](https://proxycheck.io/) and get free or paid token.
4. To use zwambro DB you may need authentication token (contact me on discord `Zwambro#8854` to create an token for your clan).
5. Open `IW4MAdmin/Configuration/ScriptPluginSettings.json`, you'll see something like:
  ```
  "VPNDetection": {
    "Author": "Zwambro",
    "Version": 1.1,
    "ZwambroAPI": "PASTZWAMBROAPIHERE",
    "ProxycheckAPI": "PASTPROXYCHECKAPIHERE",
    "MaxLevel": 2,
    "MaxConnections": 200,
    "AllowedVPNUsers": []
  }
  ```
6. Replace `PASTZWAMBROAPIHERE` with **Zwambro API** token. 
7. Replace `PASTPROXYCHECKAPIHERE` with your **proxycheck** token.
8. Change **MaxLevel** value if you want, this levels number:
   ```
   User = 0,
   Flagged = 1,
   Trusted = 2,
   Moderator = 3,
   Administrator = 4,
   SeniorAdmin = 5,
   Owner = 6,
   Creator = 7
   ```
10. Change **maxConnections** value if you want.
11. Have fun.

### Special thanks and acknowledgements
- DANGER clan for testing.
- IW4Madmin developers.
