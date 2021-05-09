var plugin = {
    author: 'Zwambro',
    version: 1.0,
    name: 'VPN Detection Plugin',

    // enable or disable the plugin, to disable it turn true to false.
    enabled: true,

    // Contact me on discord Zwambro#8854 to get the token.
    zwambroapi: "",
    //Visit www.proxycheck.io and create an account to get your API token.
    proxycheckapi : "",

    //If player connections less than maxConnections value will be infected by the plugin.
    maxConnections: 200,

    // Ranks less than maxLevel value will be infected by the plugin.
    maxLevel: { 'trusted': 2 },

    manager: null,
    logger: null,

    vpnExceptionIds: [],


    checkZwanbroDb: function (origin) {

        this.logger.WriteInfo('Checking Zwambro DB');

        var usingVPN = false;

        try {
            var cl = new System.Net.Http.HttpClient();
            cl.DefaultRequestHeaders.Add("Authorization", "Token " + this.zwambroapi);
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
            var re2 = cl2.GetAsync('http://proxycheck.io/v2/' + origin.IPAddressString + '?key=' + this.proxycheckapi + '&vpn=1').Result;
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
            var data = {"ip": origin.IPAddressString};
            client1.DefaultRequestHeaders.add("Authorization", "Token " + this.zwambroapi);
            var result1 = client1.PostAsync("https://zwambro.pw/antivpn/addvpn", new System.Net.Http.StringContent(JSON.stringify(data), System.Text.Encoding.UTF8, "application/json")).Result;
            var resCl1 = result1.Content;
            var toJson1 = JSON.parse(resCl1.ReadAsStringAsync().Result);
            resCl1.Dispose();
            result1.Dispose();
            client1.Dispose();
            output = toJson1.banned;
            if(output) {
                return true;
            }
        } catch (e) {
            this.logger.WriteWarning('There was a problem adding this IP to ZwambroDB: ' + e.message);
        }
    },

    onEventAsync: function (gameEvent, server) {

        if (!this.enabled) {
            return;
        }

        if (gameEvent.Type === 4) {
            var exempt = false;
            this.vpnExceptionIds.forEach(function (id) {
                if (id === gameEvent.Origin.ClientId) {
                    exempt = true;
                    return false;
                }
            });

            if (!gameEvent.Origin.IsIngame || gameEvent.Origin.Level >= this.maxLevel['trusted'] || gameEvent.Origin.Connections > this.maxConnections) {
                server.Logger.WriteInfo('Ignoring check for client ' + gameEvent.Origin.Name);
                return;
            }
            else if (exempt) {
                server.Logger.WriteInfo('This id @' + gameEvent.Origin.ClientId + 'on vpnExceptionIds list');
                return;
            }
            else {
                this.logger.WriteInfo(gameEvent.Origin.Name + ' (' + gameEvent.Origin.IPAddressString + ') will be checked now');
                if (this.checkZwanbroDb(gameEvent.Origin)) {
                    this.logger.WriteInfo('' + gameEvent.Origin.Name + '(' + gameEvent.Origin.IPAddressString + ') is using a VPN');
                    gameEvent.Origin.Kick(_localization.LocalizationIndex["SERVER_KICK_VPNS_NOTALLOWED"], _IW4MAdminClient);
                    return;

                } else if (this.checkXdefconDb(gameEvent.Origin)){
                    this.addVpnToDb(gameEvent.Origin);
                    this.logger.WriteInfo('' + gameEvent.Origin.Name + '(' + gameEvent.Origin.IPAddressString + ') is using a VPN');
                    gameEvent.Origin.Kick(_localization.LocalizationIndex["SERVER_KICK_VPNS_NOTALLOWED"], _IW4MAdminClient);
                    return;

                } else if (this.checkProxycheckDb(gameEvent.Origin)){
                    this.addVpnToDb(gameEvent.Origin);
                    this.logger.WriteInfo('' + gameEvent.Origin.Name + '(' + gameEvent.Origin.IPAddressString + ') is using a VPN');
                    gameEvent.Origin.Kick(_localization.LocalizationIndex["SERVER_KICK_VPNS_NOTALLOWED"], _IW4MAdminClient);
                    return;

                } else if (this.checkIpComDb(gameEvent.Origin)){
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
    },

    onUnloadAsync: function () {
    },

    onTickAsync: function (server) {
    }
};