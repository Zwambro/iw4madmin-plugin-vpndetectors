/*
Copyright (c) 2021 Ouchekkir Abdelmouaine

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

let allowedVpnsIds = [];

const commands = [{
    name: "allowvpn",
    description: "allow vpn user",
    alias: "av",
    permission: "SeniorAdmin",
    targetRequired: true,
    arguments: [{
        name: "clientname/@clientid",
        required: true
    }],
    execute: (gameEvent) => {
        var db_players = gameEvent.Owner.Manager.GetClientService().FindClientsByIdentifier(gameEvent.Data);
        if (db_players) {
            if (!allowedVpnsIds.includes(gameEvent.Target.ClientId)) {
                allowedVpnsIds.push(gameEvent.Target.ClientId);
                _configHandler.SetValue("AllowedVPNUsers", allowedVpnsIds);
                gameEvent.Origin.Tell("This ID (@" + gameEvent.Target.ClientId + ") has been added to AllowedVPNUsers list");
            }else{
                gameEvent.Origin.Tell("This ID (@" + gameEvent.Target.ClientId + ") already on AllowedVPNUsers list");
            }
        }
    }
},
{
    name: "denyvpn",
    description: "deny vpn user",
    alias: "dv",
    permission: "SeniorAdmin",
    targetRequired: true,
    arguments: [{
        name: "clientname/@clientid",
        required: true
    }],
    execute: (gameEvent) => {
        var db_players = gameEvent.Owner.Manager.GetClientService().FindClientsByIdentifier(gameEvent.Data);
        if (db_players) {
            if (allowedVpnsIds.includes(gameEvent.Target.ClientId)) {
                for( var i = 0; i < allowedVpnsIds.length; i++){
                    if ( allowedVpnsIds[i] === gameEvent.Target.ClientId) {
                        allowedVpnsIds.splice(i, 1);
                    }
                }
                _configHandler.SetValue("AllowedVPNUsers", allowedVpnsIds);
                gameEvent.Origin.Tell("This ID (@" + gameEvent.Target.ClientId + ") has been deleted from AllowedVPNUsers list");
            }else{
                gameEvent.Origin.Tell("This ID (@" + gameEvent.Target.ClientId + ") not in AllowedVPNUsers list");
            }
        }
    }
}];
const plugin = {
    author: 'Zwambro',
    version: 1.4,
    name: 'VPNDetection',

    configHandler: null,
    manager: null,
    logger: null,

    checkZwanbroDb: function (origin) {

        this.logger.WriteInfo('Checking Zwambro DB');

        var usingVPN = false;
        try {
            var cl = new System.Net.Http.HttpClient();
            cl.DefaultRequestHeaders.Add("Authorization", "Token " + this.configHandler.GetValue("ZwambroAPI"));
            var re = cl.GetAsync("https://zwambro.pw/antivpn/checkvpn?ip=" + origin.IPAddressString).Result;
            var co = re.Content;
            var parsedJSON = JSON.parse(co.ReadAsStringAsync().Result);
            co.Dispose();
            re.Dispose();
            cl.Dispose();
            usingVPN = parsedJSON.vpn

            if (usingVPN) {
                return true;
            }
        } catch (e) {
            this.logger.WriteWarning('There was a problem checking client IP on zwambro.pw ' + e.message);
        }
    },

    checkXdefconDb: function (origin) {
        this.logger.WriteInfo('Checking xdefcon DB');

        var usingVPN1 = false;
        try {
            var cl1 = new System.Net.Http.HttpClient();
            var re1 = cl1.GetAsync('https://api.xdefcon.com/proxy/check/?ip=' + origin.IPAddressString).Result;
            var userAgent = 'IW4MAdmin-' + this.manager.GetApplicationSettings().Configuration().Id;
            cl1.DefaultRequestHeaders.Add('User-Agent', userAgent);
            var co1 = re1.Content;
            var parsedJSON1 = JSON.parse(co1.ReadAsStringAsync().Result);
            co1.Dispose();
            re1.Dispose();
            cl1.Dispose();
            usingVPN1 = parsedJSON1.proxy;
            if (usingVPN1) {
                this.logger.WriteInfo('xdefcon DB detect this ip (' + origin.IPAddressString + ') as a VPN');
                return true;
            }
        } catch (e) {
            this.logger.WriteWarning('There was a problem checking client IP on xdefcon ' + e.message);
        }
    },

    checkProxycheckDb: function (origin) {
        this.logger.WriteInfo('Checking proxycheck DB');

        var usingVPN2 = "no";

        try {
            var cl2 = new System.Net.Http.HttpClient();
            var re2 = cl2.GetAsync('http://proxycheck.io/v2/' + origin.IPAddressString + '?key=' + this.configHandler.GetValue("ProxycheckAPI") + '&vpn=1').Result;
            var co2 = re2.Content;
            var parsedJSON2 = JSON.parse(co2.ReadAsStringAsync().Result);
            co2.Dispose();
            re2.Dispose();
            cl2.Dispose();

            usingVPN2 = parsedJSON2[origin.IPAddressString].proxy;

            if (usingVPN2 == 'yes') {
                return true;
            }
        } catch (e) {
            this.logger.WriteWarning('There was a problem checking client IP on proxycheck.io ' + e.message);
        }
    },

    checkIpComDb: function (origin) {
        this.logger.WriteInfo('Checking ip-api DB');

        var usingVPN3 = false;

        try {
            var cl3 = new System.Net.Http.HttpClient();
            var re3 = cl3.GetAsync('http://ip-api.com/json/' + origin.IPAddressString + '?fields=status,mobile,proxy,hosting,query').Result;
            var co3 = re3.Content;
            var parsedJSON3 = JSON.parse(co3.ReadAsStringAsync().Result);
            co3.Dispose();
            re3.Dispose();
            cl3.Dispose();

            usingVPN3 = parsedJSON3.proxy;

            if (usingVPN3) {
                return true;
            }
        } catch (e) {
            this.logger.WriteWarning('There was a problem checking client IP on ip-api.com ' + e.message);
        }
    },
    addVpnToDb: function (origin) {

        var output = false;

        try {
            var client1 = new System.Net.Http.HttpClient();
            var data = {
                "ip": origin.IPAddressString
            };
            client1.DefaultRequestHeaders.add("Authorization", "Token " + this.configHandler.GetValue("ZwambroAPI"));
            var result1 = client1.PostAsync("https://zwambro.pw/antivpn/addvpn", new System.Net.Http.StringContent(JSON.stringify(data), System.Text.Encoding.UTF8, "application/json")).Result;
            var resCl1 = result1.Content;
            var toJson1 = JSON.parse(resCl1.ReadAsStringAsync().Result);
            resCl1.Dispose();
            result1.Dispose();
            client1.Dispose();
            output = toJson1.banned;
            if (output) {
                return true;
            }
        } catch (e) {
            this.logger.WriteWarning('There was a problem adding this IP to ZwambroDB: ' + e.message);
        }
    },
    onEventAsync: function (gameEvent, server) {

        if (gameEvent.TypeName === 'Join') {
            var exempt = false;
            allowedVpnsIds.forEach(function (id) {
                if (id == gameEvent.Origin.ClientId) {
                    exempt = true;
                    return false;
                }
            });

            if (!gameEvent.Origin.IsIngame || (gameEvent.Origin.LevelInt >= this.configHandler.GetValue("MaxLevel")) || (gameEvent.Origin.Connections > this.configHandler.GetValue("MaxConnections"))) {
                server.Logger.WriteInfo('Ignoring check for client ' + gameEvent.Origin.Name);
                return;
            } else if (exempt) {
                server.Logger.WriteInfo('This id @' + gameEvent.Origin.ClientId + ' on AllowedVPNUsers list');
                return;
            } else {
                this.logger.WriteInfo(gameEvent.Origin.Name + ' (' + gameEvent.Origin.IPAddressString + ') will be checked now');
                if (this.checkZwanbroDb(gameEvent.Origin)) {
                    this.logger.WriteInfo('' + gameEvent.Origin.Name + '(' + gameEvent.Origin.IPAddressString + ') is using a VPN');
                    gameEvent.Origin.Kick(_localization.LocalizationIndex["SERVER_KICK_VPNS_NOTALLOWED"], _IW4MAdminClient);
                    return;

                } else if (this.checkXdefconDb(gameEvent.Origin)) {
                    this.addVpnToDb(gameEvent.Origin);
                    this.logger.WriteInfo('' + gameEvent.Origin.Name + '(' + gameEvent.Origin.IPAddressString + ') is using a VPN');
                    gameEvent.Origin.Kick(_localization.LocalizationIndex["SERVER_KICK_VPNS_NOTALLOWED"], _IW4MAdminClient);
                    return;

                } else if (this.checkProxycheckDb(gameEvent.Origin)) {
                    this.addVpnToDb(gameEvent.Origin);
                    this.logger.WriteInfo('' + gameEvent.Origin.Name + '(' + gameEvent.Origin.IPAddressString + ') is using a VPN');
                    gameEvent.Origin.Kick(_localization.LocalizationIndex["SERVER_KICK_VPNS_NOTALLOWED"], _IW4MAdminClient);
                    return;

                } else if (this.checkIpComDb(gameEvent.Origin)) {
                    this.addVpnToDb(gameEvent.Origin);
                    this.logger.WriteInfo('' + gameEvent.Origin.Name + '(' + gameEvent.Origin.IPAddressString + ') is using a VPN');
                    gameEvent.Origin.Kick(_localization.LocalizationIndex["SERVER_KICK_VPNS_NOTALLOWED"], _IW4MAdminClient);
                    return;

                } else {
                    this.logger.WriteInfo('' + gameEvent.Origin.IPAddressString + ' is not a VPN');
                }
            }
        }
    },

    onLoadAsync: function (manager) {
        this.manager = manager;
        this.logger = manager.GetLogger(0);
        this.configHandler = _configHandler;
        this.allowedVpnsIds = [];

        this.configHandler.SetValue("Author", this.author);
        this.configHandler.SetValue("Version", this.version);


        zwambroApiConf = this.configHandler.GetValue("ZwambroAPI");
        proxycheckApiConf = this.configHandler.GetValue("ProxycheckAPI");
        maxlevelConf = this.configHandler.GetValue("MaxLevel");
        maxConnectionsConf = this.configHandler.GetValue("MaxConnections");

        const whiteList = this.configHandler.GetValue('AllowedVPNUsers');
        if (whiteList !== undefined) {
            whiteList.forEach(element => {
                const pk = (element);
                allowedVpnsIds.push(pk)
            });
        } else {
            this.configHandler.SetValue('AllowedVPNUsers', []);
        }
        if (zwambroApiConf === undefined) {
            this.configHandler.SetValue("ZwambroAPI", 'PAST_ZWAMBRO_API_HERE');
        }
        if (proxycheckApiConf === undefined) {
            this.configHandler.SetValue("ProxycheckAPI", 'PAST_PROXYCHECK_API_HERE');
        }
        if (maxlevelConf === undefined) {
            this.configHandler.SetValue("MaxLevel", 2);
        }
        if (maxConnectionsConf === undefined) {
            this.configHandler.SetValue("MaxConnections", 200);
        }
        this.logger.WriteInfo(`Loaded VPNBlocker (${this.version}) by Zwambro`);
    },

    onUnloadAsync: () => {
    },

    onTickAsync: server => {
    }
};
