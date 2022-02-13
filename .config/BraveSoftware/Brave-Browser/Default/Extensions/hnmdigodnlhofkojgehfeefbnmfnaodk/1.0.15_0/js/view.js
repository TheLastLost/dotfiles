function MinijuegosView(cfg){
    /* Self reference */
    var self     = this,
        debug = true;

    /* Private properties */
    /** @var bgInstance MinijuegosExtBackground **/
    var bgInstance = null;

    // Load View
    var config = {
        userWidgetSelector : '.js-user-widget',
        userInfoLoadIntervalSec : 60,
        gamesWidgetSelector : ".js-games-widget",
        gameListWrapperSelector : ".js-game-list-wrapper",
        gameCardItemTemplate: "<div class='game-card-item card-item'><a href='%href%' data-utm-campaign='game-link'><img src='%imgSrc%' width='105px' height='72px' /></a></div>",
        eventCardItemTemplate: "<div class='event-card-item card-item'><a href='%href%' data-utm-campaign='event-link'><img src='%imgSrc%' width='' height='72px' /></a></div>",
        // "backgroundPage": chrome.extension.getBackgroundPage().MinijuegosExtBackground
        notificationModuleSelector: '.js-notification',
        localePickerSelector: '.js-locale-picker',
        notificationDefaultClassType: "info",
        notificationDefaultSecsDuration: 4
    };

    // Events triggered
    this.eventListeners = {
        games_loaded: null,
        user_info_loaded: null
    };

    /* DOM STUFF */
        var $body,
            $userWidget,
            $gamesWidget,
            $gameLists,
            $notification,
            $localePicker;

    /* Timeout instances control vars */
    var notificationTimeoutInstance;

    /*****************************************************************************************
     * ▼ User-Related Methods
     *****************************************************************************************/

    var loadUserData = function(userInfo) {
        log("loadUserData called");
        // var userInfo = bgInstance.user.getUserInfo();
        if (typeof userInfo == "object") {
            $.each(userInfo, function(name,value) {
                var $targets = $("*[data-user-info-field='"+name+"']");
                $targets.each(function(el) {
                    var $this = $(this),
                        $thisValue = ($this.attr("value") == "") ? null : $this.attr("value");
                    if ($thisValue == value) { return true; } // Skip if value has not changed
                    // HTML CASE
                    if ($this.data("type") == "html") {
                        $this.html(value).attr("value", value);
                    }
                    if ($this.data("type") == "value") {
                        $this.attr("value", value);
                    }
                    if ($this.data("type") == "img") {
                        $this.attr("src",value).attr("value", value);
                    }
                    if ($this.data("type") == "css-width-percent") {
                        $this.css("width",value+"%").attr("value", value);
                    }
                    if ($this.data("type") == "css-class") {
                        $this.removeClass($this.attr("value")).addClass(value).attr("value", value);
                    }
                    if ($this.data("type") == "css-background-image") {
                        $this.css("background-image","url("+value+")").attr("value", value);
                    }
                    if ($this.data("type") == "href-placeholder") {
                        $this.attr("href",$this.attr("href").split("%placeholder%").join(value)).attr("value", value);
                    }
                });
            });
        }
    };

    /*****************************************************************************************
     * ▼ Games-Related Methods
     *****************************************************************************************/

    /**
     * Object format:
     * { keep_playing : [{ name: '', href: '', img_src : '' }, { href: '', img_src : '' } ... ]
      *  favorites : { href: '', img_src : '' }
      * }
     * @param gamesInfo
     */
    var loadGameData = function(gamesInfo) {
        log("loadGameData called");
        if (typeof gamesInfo == "object") {
            $.each(gamesInfo, function(listTypeName,listElements) {
                var $targetList = $gameLists.filter("[data-list-type='"+listTypeName+"']"),
                    $listZeroCase = $targetList.find(".zero-case");
                if ($targetList.length == 0 || $listZeroCase.length == 0) {
                    log("loadGameData - List " + listTypeName + " not found in markup, skipping it.")
                    return true; } // continue if list has not been found
                // Empty list
                $targetList.find(".card-item").remove();
                $.each(listElements, function(index,listElement) {
                    var cardItemMarkup,
                        $cardItem;
                    if (!typeof listElement == "object" || !listElement.hasOwnProperty("href") || !listElement.hasOwnProperty("img_src")) {
                        log("loadGameData - Item with invalid format found in list, skipping it.");
                        log(listElement);
                        return true; }
                    // Event card type?
                    if (listElement.hasOwnProperty("type") && listElement.type == "event") {
                        cardItemMarkup = config.eventCardItemTemplate.split("%href%").join(listElement.href).split("%imgSrc%").join(listElement.img_src);
                    } else { // Game card Item
                        cardItemMarkup = config.gameCardItemTemplate.split("%href%").join(listElement.href).split("%imgSrc%").join(listElement.img_src);
                    }
                    $cardItem = $(cardItemMarkup);
                    $listZeroCase.before($cardItem);
                    //$targetList.insertBefore(".zero-case",$gameCardItem); // Append the element
                });
            });
            $gamesWidget.attr("data-loaded",1);
        }
    };

    /*****************************************************************************************
     * ▼ DOM Initialisation methods
     *****************************************************************************************/

    var initLocalePicker = function() {
        var activeLocale;
        if ($localePicker.length == 0 ) { return false; }
        if (!bgInstance.hasOwnProperty("i18n") && !bgInstance.i18n.hasOwnProperty("active_locale")) { return false; }
        activeLocale = bgInstance.i18n.active_locale;
        $localePicker.val(activeLocale);
    };

    /*****************************************************************************************
     * ▼ Event Callbacks Definitions
     *****************************************************************************************/

    var onUserInfoLoaded = function(userInfo) {
        log("onUserInfoLoaded called");
        if (typeof userInfo == "object") {
            loadUserData(userInfo);
        }
    };

    /**
     * Games loaded callback
     * @param games
     */
    var onGamesInfoLoaded = function(gamesInfo) {
        log("onGamesInfoLoaded called");
        if (typeof gamesInfo == "object") {
            loadGameData(gamesInfo);
        }
    };

    var onLocaleChange = function() {
        // We just simply reload the page
        window.location.reload();
    };

    /**
     * Notifies the background that the view has connected for the first time
     */
    this.onConnect = function() {
        log("onConnect method called");
        triggerBackgroundEvent("view_connect", this);
        //var port = chrome.extension.connect({
        //    name: "viewConnect"
        //});
        //port.postMessage("viewConnect");
        //port.onMessage.addListener(function(msg) {
        //    console.log("message recieved" + msg);
        //});
    };

    /*****************************************************************************************
     * ▼ Event Helpers
     *****************************************************************************************/

    /**
    * Register a closure function for an event
    * i.e: registerEventListener("view_blabla",function() {console.log('die');});
    */
    this.registerEventListener = function(eventId, triggerFunction) {
        if (typeof triggerFunction=="function" && eventId!=null) {
            if (this.eventListeners[eventId]==null) this.eventListeners[eventId]= [];
            this.eventListeners[eventId].push(triggerFunction);
            return true;
        } else return false;
    };


    /**
     * Triggers an event on this view instance
     */
    this.triggerEvent = function(eventId, parameter) {
        log("Trigger "+eventId+" event called ");
        log(parameter);
        if (typeof parameter == "undefined") parameter = false;
        if (this.eventListeners[eventId] instanceof Array) {
            for(var i=0;i<this.eventListeners[eventId].length;i++) {
                if ( this.eventListeners[eventId][i](parameter) == false ) return false; // stop bubbling
            }
        }
        return true;
    };

    /**
     * Outgoing communication bridge method - Launches an event on the background
     * @param eventId
     * @param parameter
     */
    var triggerBackgroundEvent = function(eventId, parameter) {
        log("Trigger "+eventId+" Background event called ");
        log(parameter);
        if (bgInstance === undefined || typeof bgInstance !== "object" || !bgInstance.hasOwnProperty("triggerEvent")) {
            log("triggerBackgroundEvent - Couldn't validate bgInstance, halting");
            return false;
        }
        bgInstance.triggerEvent(eventId, parameter);
    };

    var setupEventListeners = function() {
        log("Setting-up event listeners");
        self.registerEventListener("games_info_loaded", onGamesInfoLoaded);
        self.registerEventListener("user_info_loaded", onUserInfoLoaded);
        //self.registerEventListener("new_locale_set", onLocaleChange);
        /** Etc.. **/

        // GENERIC LINK LISTENER

        $body.on("click", "a", function(ev) {
            var $a, $href, campaign, qs, glue = "?";
            ev.preventDefault();
            $a = $(this);
            campaign = $a.data("utm-campaign");
            $href = $a.attr("href");
            if ($href.indexOf(glue) > -1 ) { glue = "&"; }
            $href = $href+glue+"utm_source=minijuegos&utm_medium=chrome-extension" + (campaign ? "&utm_campaign="+campaign : "");
            if ($href !== undefined) {
                // Track Event into Analytics
                //if (bgInstance.hasOwnProperty("analytics") && bgInstance.analytics.hasOwnProperty("trackEvent")) {
                //    bgInstance.analytics.trackEvent("View-Link",campaign);
                //}
                chrome.tabs.create({'url': $href});
            }
        });

        if ($localePicker.length > 0 ) {
            $body.on("change", config.localePickerSelector, function(ev) {
                ev.preventDefault();
                triggerBackgroundEvent("locale_change", $(this).val());
            });
        }


        // Notifications testing
        // self.showNotification("Nas pavos canicas", "info", 10);

    };

    /*****************************************************************************************
     * ▼ Helpers
     *****************************************************************************************/

    var log = function(msg) {
        if (!debug) { return false;}
        if (typeof msg == "object") {
            console.dir(msg);
        }else{
            console.log("[>_MiniChromeExt POPUP]$ "+msg);
        }
    };

    this.showNotification = function(msg,classType,duration) {
        if ($notification.length == 0) { return false; }
        if (classType === undefined) { classType = config.notificationDefaultClassType; }
        if (duration === undefined) { duration = config.notificationDefaultSecsDuration; }
        $notification.find(".message").html(msg);
        $notification.removeClass("success info error").addClass(classType);
        $notification.addClass("shown");
        if (notificationTimeoutInstance) { clearTimeout(notificationTimeoutInstance); }
        notificationTimeoutInstance = setTimeout(function() { $notification.removeClass("shown");}, duration*1000);

        //chrome.browserAction.setBadgeBackgroundColor({color:[60, 225, 100, 160]}); /* R G B ALPHA */
        //chrome.browserAction.setBadgeText({text:"12"});

    };

    /**
     * Parses the view's HTML searching for __MSG_******__ and replaces them with the proper translation
     */
    this.i18nTranslateHTML = function() {
        if (!bgInstance.hasOwnProperty("i18n") && !bgInstance.i18n.hasOwnProperty("msg")) { log("i18nTranslateHTML - I18n Module seems not initialized, halting"); }
        var objects = document.getElementsByTagName('html');
        for (var j = 0; j < objects.length; j++)
        {
            var obj = objects[j];
            var htmlToString = obj.innerHTML.toString();
            var parsedHTML = htmlToString.replace(/__MSG_(\w+)__/gi, function(match, v1) {
                return v1 ? bgInstance.i18n.msg(v1) : "";
            });

            if(parsedHTML != htmlToString) { obj.innerHTML = parsedHTML;}
        }
    };

    /**
     * Analytics module
     */

    this.analytics = new function() {

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
            accountId : "UA-228458-1"
        };

        selfAnalytics.init = function() {
            log("Google Analytics - Initializing");
            if (!config.enabled || _init) { return false; }

            _gaq = _gaq || [];
            _gaq.push(['_setAccount', config.accountId]);
            // Track this popup pageview
            _gaq.push(['_trackPageview']);

            ga = document.createElement('script'); ga.type = 'text/javascript'; ga.async = true;
            ga.src = config.src;
            s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(ga, s);

            _init = true;
        };

    };

    /*****************************************************************************************
     * ▼ Background attachment
     *****************************************************************************************/

    this.attachBackground = function() {
        // Load params
        if (cfg !== undefined && cfg.hasOwnProperty("backgroundPage")) {
            bgInstance = receivedConfig.backgroundPage;
        } else {
            bgInstance = chrome.extension.getBackgroundPage().MinijuegosExtBackground
        }

    };

    /*****************************************************************************************
     * ▼ Readiness / initialization / current state
     *****************************************************************************************/

    this.ready = function() {

        self.attachBackground();

        self.i18nTranslateHTML();

        $body = $('body');
        $gamesWidget = $body.find(config.gamesWidgetSelector);
        $gameLists = $body.find(config.gameListWrapperSelector);
        $notification = $body.find(config.notificationModuleSelector);
        $localePicker = $body.find(config.localePickerSelector);
        if ($localePicker.length >0 ) { initLocalePicker(); }

        setupEventListeners();

        self.onConnect();

        // Init Analytics
        //self.analytics.init();

        //this.i18nParseHTML();

    };

    this.init = function () {
        $(function() {
            self.ready();
        })
    };

    this.init();

}

this.MinijuegosView = new MinijuegosView(); /* Auto initialization of lazy modules */
