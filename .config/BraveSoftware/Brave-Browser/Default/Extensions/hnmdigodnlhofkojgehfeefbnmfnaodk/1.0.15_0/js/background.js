this.MinijuegosExtBackground = new function() {

    // Self access
    var selfBackground = this,
        debug = true;

    // API
    var SNORLEXT_URL_ROOT = chrome.i18n.getMessage("snorlextBackendUrl");
    
    var EXTENSION_VERSION = "1.0";

    // Modules instances
    this.user = null;
    this.games = null;
    this.i18n = null;
    this.lib = null;
    this.analytics = null;
    this.notifications = null;


    // Events triggered
    var eventListeners = {
        "modules_ready": null,
        "view_connect":null
    };

    /*****************************************************************************************
     * ▼ Modules
     *****************************************************************************************/


    /*********************
     *   USER MODULE
     *********************/
    var User = function (cfgOverride) {

        var selfUser = this;

        var config =  {
            loadInfoOnInit : true,
            refreshInfoIntervalSec : 7200, // 2 Hours Refresh interval rate
            minRefreshInfoIntervalSec : 7190, // 2 Hours Min Refresh interval rate
            retryFetchAfterError : false,
            defaultUserAvatarUrl : "../img/bg.png",
            keepAliveIntervalSec : 7200, // 2 min Refresh interval rate
            minAjaxFetchWaitTimeSecs : 7190
        };

        var lastLoadMS = 0,
            fetchError = false;

        /* Control vars */
        var userUpdateIntervalInstance,
            keepAliveIntervalInstance;

        // Module properties
        this.id = null;
        this.uid = null;
        this.user_name = null;

        this.progress_level = null;
        this.progress_level_percent = null;
        this.progress_total = null;
        this.ranking_position = null;
        this.ranking_trend = null;
        this.ranking_trend_value = null;

        this.gems_total = null;
        this.minicoins_total = null;

        this.avatar = null;
        this.avatar_mini = null;
        this.avatar_big = null;
        this.avatar_full = config.defaultUserAvatarUrl;
        this.avatar_body = null;

        this.logged_in = false;


        /**
         * Public visibility methods
         */

        /**
         * Public Info getter
         * @returns {{id: (boolean|*), uid: (boolean|*), user_name: (boolean|*), progress_level: (boolean|*), progress_level_percent: (boolean|*), progress_total: (boolean|*), gems_total: (boolean|*), minicoins_total: (boolean|*), avatar: boolean, avatar_mini: boolean, avatar_big: boolean, avatar_full: *, avatar_body: (boolean|*)}}
         */
        this.getUserInfo = function() {
            // If never loaded, force load
            if (!selfUser._loaded) { fetchUserData(); }

            var now = new Date().getTime();
            if (selfUser._loaded && ( now - (config.refreshInfoIntervalSec*1000) >= lastLoadMS )) { fetchUserData(); }

            return {
                logged_in : selfUser.logged_in,
                id : selfUser.id,
                uid : selfUser.uid,
                user_name : selfUser.user_name,
                progress_level : selfUser.progress_level,
                progress_level_percent : selfUser.progress_level_percent,
                progress_total : selfUser.progress_total,
                ranking_position : selfUser.ranking_position,
                ranking_trend : selfUser.ranking_trend,
                ranking_trend_value : selfUser.ranking_trend_value,
                gems_total : selfUser.gems_total,
                minicoins_total : selfUser.minicoins_total,
                avatar : selfUser.avatar,
                avatar_mini : selfUser.avatar_mini,
                avatar_big : selfUser.avatar_big,
                avatar_full : selfUser.avatar_full,
                avatar_body : selfUser.avatar_body
            }
        };

        /**
         * Public force refresh method . It also resets the fetching interval
         * @returns {{id: (boolean|*), uid: (boolean|*), user_name: (boolean|*), progress_level: (boolean|*), progress_level_percent: (boolean|*), progress_total: (boolean|*), gems_total: (boolean|*), minicoins_total: (boolean|*), avatar: boolean, avatar_mini: boolean, avatar_big: boolean, avatar_full: *, avatar_body: (boolean|*)}}
         */
        this.refreshUserInfo = function() {
            // Force fetch
            fetchUserData();
            // Refresh Interval
            scheduleFetchUserData();
        };

        var setUserDataLastRemoteFetchTs = function() {
            var now = new Date().getTime();
            log("Saving to LOCALSTORAGE last remote fetch ts: " + now);
            window.localStorage.setItem("user_data_last_fetch_ts", now);
        };

        var getUserDataLastRemoteFetchTs = function() {
            return JSON.parse(window.localStorage.getItem("user_data_last_fetch_ts"));
        };

        var persistUserDataToLocalStorage = function(userData) {
            log("Saving to LOCALSTORAGE UserData: ");
            console.dir(userData);
            if (!typeof userData === "object") { userData = {}; }
            window.localStorage.setItem("user_data", JSON.stringify(userData));
        };

        var getUserDataFromLocalStorage = function() {
            return JSON.parse(window.localStorage.getItem("user_data"));
        };

        /**
         * Private methods
         */

        var fetchUserData = function() {
            log("fetchUserData method called");

            if (fetchError && ! config.retryFetchAfterError) {
                log("fetchUserData - Previous error found, halting..");
                return false;
            }

            /**
             * Rate-Limit control
             * DO NOT FETCH if we've already fetch info LESS THAN config.minRefreshInfoIntervalSec (20) SECS AGO
             */
            var now = new Date().getTime();
            if (now - (config.minRefreshInfoIntervalSec*1000) <= lastLoadMS) {
                log("fetchUserData - RateLimit exceeded, fetch was already done less than "+config.minRefreshInfoIntervalSec+" secs ago");
                return false;
            }

            /**
             * SECOND SECURITY LAYER
             * @type {string}
             */
            var userDataFromStorage = getUserDataFromLocalStorage();
            var lastFetchTs = getUserDataLastRemoteFetchTs();
            if(lastFetchTs && userDataFromStorage && ( now - (config.minAjaxFetchWaitTimeSecs*1000) <= lastFetchTs )) {
                log("fetchUserData - LOADING FROM LOCAL STORAGE - AJAX RateLimit exceeded, fetch was already done less than "+config.minAjaxFetchWaitTimeSecs+" secs ago");
                loadUserData(userDataFromStorage);
                return false;
            }


            var userDataUrl = SNORLEXT_URL_ROOT + "/" + EXTENSION_VERSION + "/user/data";

            selfBackground.lib.ajax({
                type: "POST",
                data : {webId:selfBackground.i18n.msg("extWebId")},
                url: userDataUrl,
                success: function(xhr){
                    var response = JSON.parse(xhr.responseText);
                    if (response instanceof Object && response.hasOwnProperty("data")) {
                        // Load User info
                        loadUserData(response.data);
                        setUserDataLastRemoteFetchTs();
                        persistUserDataToLocalStorage(response.data)
                    }
                },
                error: function(xhr) {
                    // Not-logged in case. RAFA SUCKS
                    if (xhr.status == 403 || xhr.status == 401) {
                        loadUserData({});
                        setUserDataLastRemoteFetchTs();
                        persistUserDataToLocalStorage({});
                    } else {
                        selfUser._loaded = false;
                        fetchError = true;
                        log("fetchUserData error found: Return code " + xhr.status + " - Retry fetch after error value is " + config.retryFetchAfterError );
                        if (!config.retryFetchAfterError) {
                            log("fetchUserData - Clearing fetch interval..");
                            unscheduleFetchUserData();
                        }
                    }
                },
                complete: function(xhr) {}
            });
        };

        /**
         * Load data received from XHR into the user module
         * @param userData
         */
        var loadUserData = function(userData) {
            log("loadUserData method called");
            log(userData);
            if(userData instanceof Object && Object.keys(userData).length > 0 ) {
                /**
                 * @todo: Add this fields on returning info
                 * isGuest/logged-in,
                 */

                selfUser.logged_in = true;

                if(userData.hasOwnProperty("user_id")) selfUser.id = userData.user_id;
                if(userData.hasOwnProperty("user_uid")) selfUser.uid = userData.user_uid;
                if(userData.hasOwnProperty("user_name")) selfUser.user_name = userData.user_name;


                if(userData.hasOwnProperty("user_avatar")) {
                    if(userData.user_avatar.hasOwnProperty("avatar_body")) selfUser.avatar_body = userData.user_avatar.avatar_body;
                    if(userData.user_avatar.hasOwnProperty("avatar_full")) selfUser.avatar_full = userData.user_avatar.avatar_full;
                }

                if(userData.hasOwnProperty("user_economy")) {
                    if(userData.user_economy.hasOwnProperty("gems_total")) selfUser.gems_total = userData.user_economy.gems_total;
                    if(userData.user_economy.hasOwnProperty("minicoins_total")) selfUser.minicoins_total = userData.user_economy.minicoins_total;
                }

                if(userData.hasOwnProperty("user_progress")) {
                    if(userData.user_progress.hasOwnProperty("progress_level")) selfUser.progress_level = userData.user_progress.progress_level;
                    if(userData.user_progress.hasOwnProperty("progress_level_percent")) selfUser.progress_level_percent = userData.user_progress.progress_level_percent;
                    if(userData.user_progress.hasOwnProperty("progress_total")) selfUser.progress_total = userData.user_progress.progress_total;
                    if(userData.user_progress.hasOwnProperty("ranking_position")) selfUser.ranking_position = userData.user_progress.ranking_position;
                    if(userData.user_progress.hasOwnProperty("ranking_trend")) selfUser.ranking_trend = userData.user_progress.ranking_trend;
                    if(userData.user_progress.hasOwnProperty("ranking_trend_value")) selfUser.ranking_trend_value = userData.user_progress.ranking_trend_value;
                }
                
            } else { // Empty data, not logged-in case
                resetUser();
            }

            selfUser._loaded = true;
            lastLoadMS = new Date().getTime();

            // Broadcast load to views
            triggerViewEvent("user_info_loaded", selfUser.getUserInfo());

        };

        var keepAlive = function() {

            log("keepAlive method called");

            var userKeepAliveUrl = SNORLEXT_URL_ROOT + "/" + EXTENSION_VERSION + "/user/data";

            selfBackground.lib.ajax({
                type: "GET",
                url: userKeepAliveUrl,
                success: function(xhr){
                    var response = JSON.parse(xhr.responseText);
                    if (response.status !== 200 ) {
                        // Load User info
                        logout();
                    }
                },
                error: function(xhr) {
                    // Not-logged in case.
                    if (xhr.status == 403 || xhr.status == 401) {
                        logout();
                    } else {
                        log("keepAlive error found: Return code " + xhr.status);
                    }
                },
                complete: function(xhr) {}
            });
        };

        /**
         * Empty the user info
         */
        var resetUser = function() {
            selfUser.logged_in = false;
            selfUser.id = null;
            selfUser.uid = null;
            selfUser.user_name = null;
            selfUser.progress_level = null;
            selfUser.progress_level_percent = null;
            selfUser.progress_total = null;
            selfUser.ranking_position = null;
            selfUser.ranking_trend = null;
            selfUser.ranking_trend_value = null;
            selfUser.gems_total = null;
            selfUser.minicoins_total = null;
            selfUser.avatar = null;
            selfUser.avatar_mini = null;
            selfUser.avatar_big = null;
            selfUser.avatar_full = config.defaultUserAvatarUrl;
            selfUser.avatar_body = null;
        };

        /**
         * Logout Method
         */
        var logout = function() {
            resetUser();
            // Broadcast load to views
            triggerViewEvent("user_info_loaded", selfUser.getUserInfo());
        };

        /**
         * Schedules the fetching info interval
         */
        var scheduleFetchUserData = function() {
            log("Scheduling Fetch User method every "+config.refreshInfoIntervalSec+ " seconds");
            unscheduleFetchUserData();
            userUpdateIntervalInstance = setInterval(fetchUserData, config.refreshInfoIntervalSec*1000);
        };

        /**
         * Clears the fetching info interval
         */
        var unscheduleFetchUserData = function() {
            if (userUpdateIntervalInstance) { clearInterval(userUpdateIntervalInstance); }
        };

        var scheduleKeepAlive = function() {
            log("Scheduling Keep Alive method every "+config.keepAliveIntervalSec+ " seconds");
            if (keepAliveIntervalInstance) { clearInterval(keepAliveIntervalInstance); }
            keepAliveIntervalInstance = setInterval(keepAlive, config.keepAliveIntervalSec*1000);
        };

        /**
         * Is the current user on the extension guest on Miniplay?
         * @returns {boolean}
         */
        this.isGuest = function () {
            return !selfBackground.id || !selfBackground.user;
        };

        /**
         * Merges the config if override one has been provided
         */
        var initCfg = function() {
            if (cfgOverride === undefined || !cfgOverride instanceof Object) { return false; }
            config = Object.assign(config, cfgOverride);
        };

        var init = function() {

            initCfg();

            if (config.loadInfoOnInit) {
                // Force first load
                fetchUserData();
            }

            scheduleFetchUserData();

            // scheduleKeepAlive();

            log("User Module initialized");

        };

        registerEventListener("modules_ready", function () {init();} );

    };

    /*********************
     *   GAMES MODULE
     *********************/
    var Games = function (cfgOverride) {

        var selfGames = this;

        var config =  {
            loadInfoOnInit : true,
            refreshInfoIntervalSec : 7200, // 2 hours Refresh interval rate
            minRefreshInfoIntervalSec : 7190, // 2 hours Min Refresh interval rate
            retryFetchAfterError : false,
            minAjaxFetchWaitTimeSecs : 7190
        };

        var lastLoadMS = 0,
            fetchError = false;

        /** Info is stored here **/
        var gamesLists = null;


        var gamesUpdateIntervalInstance;

        /**
         * Public visibility methods
         */

        /**
         * Public method to access to info
         * @returns {*}
         */
        this.getGamesInfo = function() {
            // If never loaded, force load
            if (!selfGames._loaded) { fetchGamesData(); }

            var now = new Date().getTime();
            if (selfGames._loaded && now - (config.refreshInfoIntervalSec*1000) >= lastLoadMS) { fetchGamesData(); }

            return gamesLists;
        };

        /**
         * Public force refresh method . It also resets the fetching interval
         * @returns {list-type : [{href:'',imgSrc:'',catalogName:''},{href:'',imgSrc:'',catalogName:''}...]}
         */
        this.refreshGamesInfo = function() {
            // Force fetch
            fetchGamesData();
            // Refresh Interval
            scheduleFetchGamesData();
        };


        var setGamesDataLastRemoteFetchTs = function() {
            var now = new Date().getTime();
            log("Saving to LOCALSTORAGE last remote fetch ts: " + now);
            window.localStorage.setItem("games_data_last_fetch_ts", now);
        };

        var getGamesDataLastRemoteFetchTs = function() {
            return window.localStorage.getItem("games_data_last_fetch_ts");
        };

        var persistGamesDataToLocalStorage = function(gamesData) {
            log("Saving to LOCALSTORAGE GamesData: ");
            if (!typeof gamesData === "object") { gamesData = {}; }
            window.localStorage.setItem("games_data", JSON.stringify(gamesData));
        };

        var getGamesDataFromLocalStorage = function() {
            return JSON.parse(window.localStorage.getItem("games_data"));
        };

        /**
         * Private methods
         */

        var fetchGamesData = function() {
            log("fetchGamesData method called");

            if (fetchError && ! config.retryFetchAfterError) {
                log("fetchGamesData previous error found, halting..");
                return false;
            }

            /**
             * Rate-Limit control
             * DO NOT FETCH if we've already fetch info LESS THAN config.minRefreshInfoIntervalSec (20) SECS AGO
             */
            var now = new Date().getTime();
            if (now - (config.minRefreshInfoIntervalSec*1000) <= lastLoadMS) {
                log("fetchGamesData - RateLimit exceeded, fetch was already done less than "+config.minRefreshInfoIntervalSec+" secs ago");
                return false;
            }

            /**
             * SECOND SECURITY LAYER TO AVOID FETCHING
             * @type {string}
             */
            var gamesDataFromStorage = getGamesDataFromLocalStorage();
            var lastFetchTs = getGamesDataLastRemoteFetchTs();
            // console.log("Games Data from Storage: ");
            // console.dir(gamesDataFromStorage);
            // console.log("Last Fetch Ts: " + lastFetchTs);
            if(lastFetchTs && gamesDataFromStorage && ( now - (config.minAjaxFetchWaitTimeSecs*1000) <= lastFetchTs )) {
                log("fetchGamesData - LOADING FROM LOCAL STORAGE - AJAX RateLimit exceeded, fetch was already done less than "+config.minAjaxFetchWaitTimeSecs+" secs ago");
                loadGamesData(gamesDataFromStorage);
                return false;
            }

            var gamesDataUrl = SNORLEXT_URL_ROOT + "/" + EXTENSION_VERSION + "/games/list";

            selfBackground.lib.ajax({
                type: "POST",
                data : {webId:selfBackground.i18n.msg("extWebId")},
                url: gamesDataUrl,
                success: function(xhr){
                    var response = JSON.parse(xhr.responseText);
                    if (response instanceof Object && response.hasOwnProperty("data")) {
                        // Load User info
                        loadGamesData(response.data);
                        setGamesDataLastRemoteFetchTs();
                        persistGamesDataToLocalStorage(response.data);
                    }
                },
                error: function(xhr) {
                    selfGames._loaded = false;
                    fetchError = true;
                    log("fetchGamesData - Error found: Return code " + xhr.status + " - Retry fetch after error value is " + config.retryFetchAfterError );
                    if (!config.retryFetchAfterError) {
                        log("fetchGamesData - Clearing fetch interval..");
                        unscheduleFetchGamesData();
                    }
                },
                complete: function(xhr) {}
            });
        };

        /**
         * Load data received from XHR into the user module
         * @param gamesData
         */
         var loadGamesData = function(gamesData) {
            log("loadGamesData method called");
            log(gamesData);
            if(typeof gamesData == "object") {
                gamesLists = gamesData;
                selfGames._loaded = true;
                lastLoadMS = new Date().getTime();
            }

            // Broadcast load to views
            triggerViewEvent("games_info_loaded", selfGames.getGamesInfo());

        };

        /**
         * Schedules the fetching info interval
         */
        var scheduleFetchGamesData = function() {
            log("Scheduling Fetch Games method every "+config.refreshInfoIntervalSec+ " seconds");
            unscheduleFetchGamesData();
            gamesUpdateIntervalInstance = setInterval(fetchGamesData, config.refreshInfoIntervalSec*1000);
        };

        /**
         * Clears the fetching info interval
         */
        var unscheduleFetchGamesData = function() {
            if (gamesUpdateIntervalInstance) { clearInterval(gamesUpdateIntervalInstance); }
        };

        /**
         * Overrides cfg if new one has been passed to constructor
         * @returns {boolean}
         */
        var initCfg = function() {
            if (cfgOverride === undefined || !cfgOverride instanceof Object) { return false; }
            config = Object.assign(config, cfgOverride);
        };

        var init = function() {

            initCfg();

            if (config.loadInfoOnInit) {
                fetchGamesData();
            }

            scheduleFetchGamesData();

            log("Games Module initialized");
        };

        registerEventListener("modules_ready", init );

    };

    /*********************
     *   LIB MODULE
     *********************/
    var Lib = function () {

        var selfLib = this;

        /**
         * Performs an Ajax request, pretty similar to the jQuery $.ajax() method
         * @param requestObject
         */

        this.ajax = function(requestObject) {

            var cfg = {
                data :  {},
                success : function(xhr) {},
                error: function() {},
                complete: function() {},
                url: null,
                type: "GET"
            };

            // Override
            cfg = Object.assign(cfg, requestObject);

            // XHR Init
            var xhr = new XMLHttpRequest();

            xhr.open(cfg.type, cfg.url, true);

            if (cfg.type.toUpperCase() == "POST") {
                xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
            }

            // Callbacks
            xhr.onreadystatechange = function () {
                if (xhr.readyState == 4) {
                    if(xhr.status >= 200 && xhr.status < 300) {
                        if(typeof cfg.success == "function") cfg.success(xhr);
                    } else {
                        if(typeof cfg.error == "function") cfg.error(xhr);
                    }
                    if(typeof cfg.complete == "function") cfg.complete(xhr);
                }
            };

            // Send XHR Req
            if(cfg.data !== null && cfg.data instanceof Object) {
                xhr.send(selfLib.serialize(cfg.data));
            } else {
                xhr.send();
            }
        };

        this.serialize = function(json) {
            return Object.keys(json).map(function(key) {
                    return encodeURIComponent(key) + '=' +
                        encodeURIComponent(json[key]);
                }).join('&');
        };

        var init = function() {

            log("Lib Module initialized");
        };

        registerEventListener("modules_ready", init );
    };

    var Analytics = function () {

        var selfAnalytics = this,
            _init = false,
            _gaq,
            ga,
            s;

        /*
         $this->set("trackingStandardAnalytics01","UA-228458-1");
         $this->set("trackingStandardAnalytics02","UA-33368816-1");
         $this->set("trackingUniversalAnalytics","UA-55950411-1");
         */
        var config = {
            enabled : true,
            src : 'https://ssl.google-analytics.com/ga.js',
            accountId : "UA-93338784-1"
        };

        //['_trackEvent', 'Navigation', 'LastPlayedGames', 'click-most-played']
        this.trackEvent = function(eventType, eventName, eventValue) {
            if (eventType === undefined) {return;}
            if (eventValue === undefined) {eventValue = "";}
            trackAnalyticsEvent(["_trackEvent", "ChromeExtension", eventType, eventName, eventValue]);
        };

        /**
         * Private method
         * @param eventArray
         */
        var trackAnalyticsEvent = function(eventArray) {
            var eventArray2, trackers, tracker;
            if (eventArray[0]=="_trackEvent") {
                eventArray.shift();
            }
            if (window.hasOwnProperty("_gaq") && window.hasOwnProperty("_gat")) {
                eventArray2 = eventArray.slice(0); // Clone
                // Standard analytics
                trackers = window._gat._getTrackers();
                if (trackers instanceof Array) {
                    for (var i=0; i<trackers.length; ++i) {
                        tracker = trackers[i];
                        tracker._trackEvent.apply(tracker, eventArray2);
                    }
                }
            }
        };

        var init = function() {
            if (!config.enabled || _init) { return false; }

            _gaq = _gaq || [];
            _gaq.push(['_setAccount', config.accountId]);
            // Track this background session pageview
            _gaq.push(['_trackPageview']);

            ga = document.createElement('script'); ga.type = 'text/javascript'; ga.async = true;
            ga.src = config.src;
            s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(ga, s);

            /*$.getScript( config.src, function( data, textStatus, jqxhr ) {
                console.log( data ); // Data returned
                console.log( textStatus ); // Success
                console.log( jqxhr.status ); // 200
                console.log( "Load was performed." );
            });*/

            _init = true;
            log("Analytics Module Initialized");
        };

        registerEventListener("modules_ready", init );
    };

    var I18n = function () {

        var selfI18n = this,
            _init = false;

        this.active_locale = null;

        var validLocales = ["en","es","it","pt"];
        var default_locale = "en";

        var config = {
            defaultLocaleFallback : true
        };

        this.numbers = {
            decimal_point: ".",
            thousands_separator: " "
        };

        var translations = {
            "en" : {
                /* Backend */
                "snorlextBackendUrl": "https://www.miniplay.com/api/snorlext",
                /* WEB ITEM STUFF */
                "extWebId" : "10",
                "extWebName": "miniplay",
                "extName": "Miniplay.com",
                "viewTitle": "Miniplay.com",
                "extDescription" : "The new and awesome Miniplay extension, TO PET IT!",
                "extsrctagdeferred" : "src",
                /* I18N URLS */
                "extRootUrl" : "https://www.miniplay.com",
                "extCommunityUrl" : "https://www.miniplay.com/community",
                "extGamesWithAchievementsUrl" : "https://www.miniplay.com/games-with-achievements",
                "extProfileUrl" : "https://www.miniplay.com/profile/%placeholder%",
                "extProfileFavoritesUrl" : "https://www.miniplay.com/profile/%placeholder%/favorites",
                "contentSettingsPrimaryPattern" : "https://www.miniplay.com/",
                /* CONTENT */
                "recommended": "Recommended",
                "keepPlaying": "Keep Playing",
                "yourFavorites": "Your Favorites",
                "latest": "Latest",
                "updates": "Updates",
                "mostPlayed": "Most Played",
                "viewAll": "View All",
                "login": "Login",
                "playInMiniplay" : "Play in %siteName%"
            },
            "es" : {
                "snorlextBackendUrl": "https://www.minijuegos.com/api/snorlext",
                /* WEB ITEM STUFF */
                "extWebId" : "1",
                "extWebName": "minijuegos",
                "extName": "Minijuegos.com",
                "extDescription" : "La nueva e impresionante extension de Minijuegos, para que lo petes!",
                "viewTitle": "Minijuegos.com",
                "extsrctagdeferred" : "src",
                /* I18N URLS */
                "extRootUrl" : "https://www.minijuegos.com",
                "extCommunityUrl" : "https://www.minijuegos.com/comunidad",
                "extGamesWithAchievementsUrl" : "https://www.minijuegos.com/juegos-con-logros",
                "extProfileUrl" : "https://www.minijuegos.com/perfil/%placeholder%",
                "extProfileFavoritesUrl" : "https://www.minijuegos.com/perfil/%placeholder%/favoritos",
                "contentSettingsPrimaryPattern" : "https://www.minijuegos.com/",
                /* CONTENT */
                "keepPlaying": "Sigue Jugando",
                "recommended": "Recomendados",
                "yourFavorites": "Tus Favoritos",
                "latest": "Últimos",
                "updates": "Novedades",
                "viewAll": "Ver todos",
                "login": "Entra",
                "playInMiniplay" : "Juega en %siteName%"
            },
            "it" : {
                /* Backend */
                "snorlextBackendUrl" : "https://www.minigiochi.com/api/snorlext",
                /* WEB ITEM STUFF */
                "extWebId" : "20",
                "extWebName": "minigiochi",
                "extName": "Minigiochi.com",
                "extDescription" : "The new and awesome Miniplay extension, TO PET IT!",
                "viewTitle":  "Minigiochi.com",
                "extsrctagdeferred" : "src",
                /* I18N URLS */
                "extRootUrl" :  "https://www.minigiochi.com",
                "extCommunityUrl" : "https://www.minigiochi.com/comunita",
                "extGamesWithAchievementsUrl" : "https://www.minigiochi.com/giochi-con-obiettivi",
                "extProfileUrl" : "https://www.minigiochi.com/profilo/%placeholder%",
                "extProfileFavoritesUrl" : "https://www.minigiochi.com/profilo/%placeholder%/preferiti",
                "contentSettingsPrimaryPattern" : "https://www.minigiochi.com/",
                /* CONTENT */
                "keepPlaying" : "Continua a giocare",
                "recommended" : "Consigliati",
                "yourFavorites" : "Preferiti",
                "latest": "Ultimi",
                "mostPlayed": "Più Giocati",
                "updates": "Nuovi",
                "viewAll": "Vedere tutti",
                "login": "Login",
                "playInMiniplay" : "Gioca in %siteName%"
            },
            "pt" : {
                /* Backend */
                "snorlextBackendUrl": "https://www.minijogos.com.br/api/snorlext",
                /* WEB ITEM STUFF */
                "extWebId" : "30",
                "extWebName": "minijogos",
                "extName": "Minijogos.com.br",
                "extDescription" : "The new and awesome Miniplay extension, TO PET IT!",
                "viewTitle": "Minijogos.com.br",
                "extsrctagdeferred" : "src",
                /* I18N URLS */
                "extRootUrl" : "https://www.minijogos.com.br",
                "extCommunityUrl" : "https://www.minijogos.com.br/comunita",
                "extGamesWithAchievementsUrl" : "https://www.minijogos.com.br/jogos-com-conquistas",
                "extProfileUrl" : "https://www.minijogos.com.br/perfil/%placeholder%",
                "extProfileFavoritesUrl" : "https://www.minijogos.com.br/perfil/%placeholder%/favoritos",
                "contentSettingsPrimaryPattern" : "https://www.minijogos.com.br/",
                /* CONTENT */
                "keepPlaying": "Continuar a jogar",
                "recommended": "Recomendado",
                "yourFavorites": "Favoritos",
                "latest": "Mais recentes",
                "mostPlayed": "Mais Jogados",
                "updates": "Atualizações",
                "viewAll": "Ver tudo",
                "login":"Entrar",
                "playInMiniplay" : "Jogar em %siteName%"
            }
        };

        var xlat = {}; /* Active translations container */

        /**
         * Translates a message or returns the original one
         * @param key
         * @return
         */
        this.msg = function(key){
            var msg;
            if (!_init) { log("I18n msg() - Module not initialized, halting"); return false; }
            if (xlat.hasOwnProperty(key) && xlat[key] !== "") {
                msg = xlat[key]
            } else if (config.defaultLocaleFallback && (translations[default_locale].hasOwnProperty(key) && translations[default_locale][key] !== "")) {
                msg = translations[default_locale][key];
            } else {
                msg = key;
            }
            return msg;
        };
        /**
         * Translates with variables
         * @param key
         * @param vars
         * @return
         */
        this.msv = function(key,vars) {
            if (!_init) { log("I18n msv() - Module not initialized, halting"); return false; }
            var msg = selfI18n.msg(key);
            if (typeof vars=="object") {
                for (var objectKey in vars) {
                    if (!vars.hasOwnProperty(objectKey)) continue;
                    if (typeof vars[objectKey] == "string" || typeof vars[objectKey] == "number") {
                        msg=msg.split(objectKey).join(vars[objectKey]);
                    }
                }
            }
            return msg;
        };
        /**
         * Adds a translation
         * @param key
         * @param msg
         */
        this.add = function(key,msg) {
            if (!_init) { log("I18n add() - Module not initialized, halting"); return false; }
            if (typeof key=="string" && typeof msg=="string") xlat[key]=msg;
        };

        /**
         * Adds a translation batch
         * @param {Object} batch
         */
        this.addBatch = function(batch) {
            if (!_init) { log("I18n addBatch() - Module not initialized, halting"); return false; }
            if (typeof batch != "object") return;
            for (var key in batch) {
                if (!batch.hasOwnProperty(key)) continue;
                if (typeof batch[key]=="string") xlat[key]=batch[key];
            }
        };

        // Numeric methods
        this.readNumber = function(string) {
            if (!_init) { log("I18n readNumber() - Module not initialized, halting"); return false; }
            string=string + "";
            string=string.split(selfI18n.numbers.thousands_separator).join("");
            string=string.split(selfI18n.numbers.decimal_point).join(".");
            return (Number(string)); // convert to integer or float
        };

        this.writeNumber = function(number, decimalPrecision, useThousandsSeparator) {
            if (!_init) { log("I18n writeNumber() - Module not initialized, halting"); return false; }
            var numberParts;
            var rgx = /(\d+)(\d{3})/;
            if (typeof useThousandsSeparator === "undefined") {
                useThousandsSeparator = true;
            }
            if (typeof decimalPrecision == "undefined") decimalPrecision = 0;
            number = Number(number).toFixed(parseInt(decimalPrecision)) + "";
            if (useThousandsSeparator) {
                numberParts = number.split('.');
                numberParts[1] = numberParts.length > 1 ? selfI18n.numbers.decimal_point + numberParts[1] : '';
                while (rgx.test(numberParts[0])) {
                    numberParts[0] = numberParts[0].replace(rgx, '$1' + selfI18n.numbers.thousands_separator + '$2');
                }
                return numberParts[0] + numberParts[1];
            } else {
                return number.split(".").join(selfI18n.numbers.decimal_point);
            }
        };

        /***
         * Public method that sets a new locale.
         * @param newLocale
         */
        this.setLocale = function(newLocale) {
            if (setLocalStorageLocale(newLocale)) {
                initLocale();
                triggerViewEvent("new_locale_set");
            }
        };

        /**
         * Writes localStorage Locale
         * @param newLocale
         * @returns {boolean}
         */
        var setLocalStorageLocale = function(newLocale) {
            if (newLocale === undefined || validLocales.indexOf(newLocale) == -1) { log ("Invalid locale provided " + newLocale); return false;}
            window.localStorage.setItem("locale", newLocale);
            return true;
        };

        /**
         * Sets the locale property if found in LocalStorage
         */
        var setLocaleFromLocalStorage = function() {
            var localStorageLocale = window.localStorage.getItem("locale");
            if (validLocales.indexOf(localStorageLocale) >= 0) { selfI18n.active_locale = localStorageLocale; }
        };

        var initLocale = function() {
            // setLocaleFromLocalStorage();
            // If we could not fetch from local Storage, we read it from Manifest. If this one fails, we set the config default one.
            if (!selfI18n.active_locale) {
                var manifest = chrome.runtime.getManifest();
                if (manifest.hasOwnProperty("default_locale")) {
                    selfI18n.active_locale = manifest.default_locale;
                    if (!translations.hasOwnProperty(selfI18n.active_locale)) {
                        log("Invalid locale provided ("+selfI18n.active_locale+"), overriding with default one ("+default_locale+")");
                        selfI18n.active_locale = default_locale;
                    }
                } else { // No locale config param found
                    selfI18n.active_locale = default_locale;
                }
            }
            /**
             * LOAD LOCALES
             */
            xlat = translations[selfI18n.active_locale];
        };

        var init = function() {
            if (_init) { return false;}

            initLocale();

            log("I18n Module initialized");
            _init = true;
        };

        registerEventListener("modules_ready", init );
    };

    /*****************************************************************************************
     * ▼ Private helpers
     *****************************************************************************************/

    var log = function(msg) {
        if (!debug) { return false;}
        if (typeof msg == "object") {
            console.dir(msg);
        }else{
            console.log("[>_MiniChromeExt BG]$ "+msg);
        }
    };

    /*****************************************************************************************
     * ▼ Event Callback definitions
     *****************************************************************************************/

    /**
     * Chrome context menu click listener
     * @param info
     * @param tab
     */
    var chromeContextMenuClick = function (info, tab) {
        var target;
        if (!info.hasOwnProperty("selectionText") || info.selectionText === undefined ) {
            chrome.tabs.create({'url': "https://www.minijuegos.com/"});
        } else {
            target = info.selectionText;
            target = target.toLowerCase();
            chrome.tabs.create({'url': "https://www.minijuegos.com/buscar/"+target});
        }

    };

    /**
     *  When extension gets installed create context menu
     */
    var chromeInstalled = function () {
        // creating context menu
        /*chrome.contextMenus.create({
            "title": selfBackground.i18n.msv("playInMiniplay", { "%siteName%" : selfBackground.i18n.msg("extName") }),
            "id": "open",
            "contexts": ["page", "selection", "image", "link"]
        });*/

        var pattern = selfBackground.i18n.msg("contentSettingsPrimaryPattern");
        enableFlashPlugin(pattern);
    };

    /**
     * Chrome external message receiver method, only used to check if the extension is installed
     * later we can build here a dispatcher and use it for different purposes
     * @param msg
     * @param sender
     * @param callback
     */
    var chromeExternalMessage = function(msg, sender, callback) {
        if(msg && msg.text && msg.text==="ping"){
            callback({text: "pong"});
        }
    };

    /**
     * Enable
     * @param pattern
     */
    var enableFlashPlugin = function(pattern){
        chrome.contentSettings.plugins.set(
            {
                primaryPattern: pattern,
                // resourceIdentifier: {
                //     id: "adobe-flash-player"
                // },
                setting: "allow",
                scope: ("regular")
            },
            function(){
                // debugger;
            }
        );
    };

    /**
     * Method triggered at popup show-up
     * @param view
     */
    var onViewConnect = function(view) {
        log("onViewConnect method called");
        if (view === undefined || typeof view !== "object" || !view.hasOwnProperty("triggerEvent")) {
            log("onViewConnect - Couldn't validate View instance, halting")
        }
        if (selfBackground.user) {
            // Force refresh
            selfBackground.user.refreshUserInfo();
            // Broadcast to views
            view.triggerEvent("user_info_loaded", selfBackground.user.getUserInfo());
        }
        if (selfBackground.games) {
            // Force refresh
            selfBackground.games.refreshGamesInfo();
            // Broadcast to views
            view.triggerEvent("games_info_loaded", selfBackground.games.getGamesInfo());
        }
    };

    var onLocaleChange = function(newLocale) {
        log("onLocaleChange method called, with locale "+newLocale);
        if (selfBackground.i18n) {
            selfBackground.i18n.setLocale(newLocale);
        }
    };

    /*****************************************************************************************
     * ▼ Event Helpers
     *****************************************************************************************/

    /**
     * Register a closure function for an event
     * i.e: registerEventListener("view_blabla",function() {console.log('die');});
     */
    var registerEventListener = function(eventId, triggerFunction) {
        if (typeof triggerFunction=="function" && eventId!=null) {
            if (eventListeners[eventId]==null) eventListeners[eventId]= [];
            eventListeners[eventId].push(triggerFunction);
            return true;
        } else return false;
    };

    /**
     * Triggers a background-registered event
     */
    this.triggerEvent = function(eventId, parameter) {
        log(eventListeners);
        if (typeof parameter == "undefined") parameter = false;
        if (eventListeners[eventId] instanceof Array) {
            for(var i=0;i<eventListeners[eventId].length;i++) {
                if ( eventListeners[eventId][i](parameter) == false ) return false; // stop bubbling
            }
        }
        log(eventId + " event triggered");
        return true;
    };

    /**
     * Outgoing communication bridge method - Launches an event on the views
     * @param eventName
     * @param param
     */
    var triggerViewEvent = function(eventName, param) {
        log("About to trigger " +eventName+ " event to the views");
        log(param);
        // Notify Views
        chrome.extension.getViews({type: "popup"}).forEach(function (view) {
            var viewInstance;
            if (!view.hasOwnProperty("MinijuegosView")) { return; }
            viewInstance = view.MinijuegosView;
            if (typeof(viewInstance.triggerEvent) == 'function') {
                viewInstance.triggerEvent(eventName, param);
            }
        });
    };

    var setupEventListeners = function() {
        log("Setting-up event listeners");
        registerEventListener("view_connect", onViewConnect);
        //registerEventListener("locale_change", onLocaleChange);
        /** Etc.. **/

        ///**
        // * port is the view?
        // */
        //chrome.extension.onConnect.addListener(function(port) {
        //    debugger;
        //    console.log("Connected .....");
        //    port.onMessage.addListener(function(msg) {
        //        console.log("message recieved" + msg);
        //        port.postMessage("Hi View.js");
        //    });
        //})

        chrome.runtime.onMessageExternal.addListener(
            function(request, sender, sendResponse) {
                log("background.js got an external message")
                log(request);
                log(sender);
                sendResponse({success:true});
            }
        );

    };

    /*****************************************************************************************
     * ▼ Readiness / initialization / current state
     *****************************************************************************************/

    var logInstallationDate = function() {
        var installationDate = window.localStorage.getItem("install_date");
        if (installationDate) { return false; }
        // Write it
        var now = new Date().getTime();
        window.localStorage.setItem("install_date", now);
    };

    /**
     * Modules configuration {moduleName : isEnabled}
     * @important: Add entry to enable a module
     */

    var modules = {
        "i18n" : I18n,
        "user" : User,
        "games" : Games,
        "lib" : Lib
        //"analytics" : Analytics,
        //"notifications" : Notifications
    };

    var initModules = function() {
        for (var moduleName in modules) {
            if (modules.hasOwnProperty(moduleName) && typeof modules[moduleName] == "function") {
                selfBackground[moduleName] = new modules[moduleName]();
            }
        }
        // Trigger the event that inits every module init method
        selfBackground.triggerEvent("modules_ready");
    };

    this.init = function () {

        // Init modules
        initModules();

        setupEventListeners();

        logInstallationDate();

        // Events
        chrome.runtime.onInstalled.addListener(chromeInstalled);
        /*chrome.contextMenus.onClicked.addListener(chromeContextMenuClick);*/
        chrome.runtime.onMessageExternal.addListener(chromeExternalMessage);

    };

    selfBackground.init();

};
