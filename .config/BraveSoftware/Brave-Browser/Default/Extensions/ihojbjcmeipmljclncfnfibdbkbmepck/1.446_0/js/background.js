(function () {
    'use strict';

    /*! *****************************************************************************
    Copyright (c) Microsoft Corporation.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose with or without fee is hereby granted.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
    REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
    INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
    LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
    OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
    PERFORMANCE OF THIS SOFTWARE.
    ***************************************************************************** */

    function __awaiter(thisArg, _arguments, P, generator) {
        function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
        return new (P || (P = Promise))(function (resolve, reject) {
            function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
            function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
            function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
            step((generator = generator.apply(thisArg, _arguments || [])).next());
        });
    }

    const EXTENSION_ID = chrome.runtime.id;
    const DOMAIN_NAME = 'googlecalendar.miro-apps.com';
    const DOMAIN = `https://${DOMAIN_NAME}`;
    const GOOGLE_USER_PROFILE_URL = `${DOMAIN}/googleAuth/profile`;
    const GOOGLE_LOGOUT_URL = `${DOMAIN}/googleAuth/revokeToken`;
    const MIRO_LOGOUT_URL = `${DOMAIN}/miroAuth/revokeTokens`;
    const MIRO_TEAM_LOGOUT_URL = `${DOMAIN}/miroAuth/revokeToken`;
    const MIRO_TEAMS_URL = `${DOMAIN}/api/miro/getTeams`;
    const MIRO_PICTURE_URL = `${DOMAIN}/api/miro/getPicture`;
    const MIRO_PROFILE_URL = `${DOMAIN}/api/miro/getMiroUserProfile`;
    const GET_BOARDS_URL = `${DOMAIN}/api/miro/getBoards`;
    const SEARCH_BOARDS_URL = `${DOMAIN}/api/miro/searchBoards`;
    const CREATE_BOARD_URL = `${DOMAIN}/api/miro/createBoard`;
    const SHARE_BOARD_URL = `${DOMAIN}/api/shareState`;
    const TRACK_EVENT_URL = `${DOMAIN}/api/track`;

    var EDITOR_STATE;
    (function (EDITOR_STATE) {
        EDITOR_STATE["IDLE"] = "IDLE";
        EDITOR_STATE["FULL_SCREEN"] = "FULL_SCREEN";
        EDITOR_STATE["MODAL"] = "MODAL";
    })(EDITOR_STATE || (EDITOR_STATE = {}));
    var SHARE_ROLES;
    (function (SHARE_ROLES) {
        SHARE_ROLES["NONE"] = "none";
        SHARE_ROLES["VIEWER"] = "viewer";
        SHARE_ROLES["COMMENTER"] = "commenter";
        SHARE_ROLES["EDITOR"] = "editor";
    })(SHARE_ROLES || (SHARE_ROLES = {}));
    var BACKGROUND_COMMANDS;
    (function (BACKGROUND_COMMANDS) {
        BACKGROUND_COMMANDS["SHOW_PAGE_ACTION"] = "showPageAction";
        BACKGROUND_COMMANDS["GET_COOKIE"] = "getCookie";
        BACKGROUND_COMMANDS["GET_GOOGLE_USER_PROFILE"] = "getGoogleUserProfile";
        BACKGROUND_COMMANDS["GET_MIRO_TEAMS"] = "getMiroTeams";
        BACKGROUND_COMMANDS["GET_MIRO_USER_PROFILE"] = "getMiroUserProfile";
        BACKGROUND_COMMANDS["GET_BOARDS"] = "getBoards";
        BACKGROUND_COMMANDS["GET_MIRO_PICTURE_DATA_URL"] = "getPictureDataUrl";
        BACKGROUND_COMMANDS["SEARCH_BOARDS"] = "searchBoards";
        BACKGROUND_COMMANDS["CREATE_BOARD"] = "createBoard";
        BACKGROUND_COMMANDS["SHARE_BOARD"] = "shareBoard";
        BACKGROUND_COMMANDS["LOGOUT_GOOGLE"] = "logoutGoogle";
        BACKGROUND_COMMANDS["LOGOUT_MIRO"] = "logoutMiro";
        BACKGROUND_COMMANDS["LOGOUT_MIRO_TEAM"] = "logoutMiroTeam";
        BACKGROUND_COMMANDS["TRACK_EVENT"] = "trackEvent";
    })(BACKGROUND_COMMANDS || (BACKGROUND_COMMANDS = {}));
    var MODAL_TYPE;
    (function (MODAL_TYPE) {
        MODAL_TYPE["SETTINGS"] = "settings";
        MODAL_TYPE["PICKER"] = "boardsPicker";
        MODAL_TYPE["TEAM_CHOOSE"] = "teamChoose";
        MODAL_TYPE["FEEDBACK"] = "feedback";
        MODAL_TYPE["PERMISSIONS"] = "permissions";
    })(MODAL_TYPE || (MODAL_TYPE = {}));

    function makeFetch(method, url, token, headers, body) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!token) {
                return null;
            }
            const res = yield fetch(url, Object.assign({ method, headers: Object.assign({ Authorization: `Bearer ${token}` }, headers) }, (body ? { body: JSON.stringify(body) } : {})));
            let data;
            if (res.headers.get('Content-Type').includes('application/json')) {
                data = yield res.json();
            }
            else {
                data = yield res.text();
            }
            if (data.statusCode) {
                return null;
            }
            return data;
        });
    }
    function makeCreateBoardReq(sendResponse, token, boardData) {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield makeFetch('POST', CREATE_BOARD_URL, token, { 'Content-Type': 'application/json' }, boardData);
            sendResponse({ result: result });
        });
    }
    function makeShareBoardReq(sendResponse, token, shareData) {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield makeFetch('POST', SHARE_BOARD_URL, token, { 'Content-Type': 'application/json' }, shareData);
            sendResponse({ result: result });
        });
    }
    function makeGoogleUserProfileReq(sendResponse, token) {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield makeFetch('GET', GOOGLE_USER_PROFILE_URL, token);
            sendResponse({ result: result });
        });
    }
    function makeMiroTeamsReq(sendResponse, token) {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield makeFetch('GET', MIRO_TEAMS_URL, token);
            sendResponse({ result: result });
        });
    }
    function makeLogoutGoogleReq(sendResponse, token) {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield makeFetch('POST', GOOGLE_LOGOUT_URL, token);
            sendResponse({ result: result });
        });
    }
    function makeLogoutMiroReq(sendResponse, token) {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield makeFetch('POST', MIRO_LOGOUT_URL, token);
            sendResponse({ result: result });
        });
    }
    function makeLogoutMiroTeamReq(sendResponse, token, teamId) {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield makeFetch('POST', MIRO_TEAM_LOGOUT_URL, token, { 'Content-Type': 'application/json' }, { teamId });
            sendResponse({ result: result });
        });
    }
    function arrayBufferToBase64(buffer) {
        return btoa(Array.from(new Uint8Array(buffer))
            .map((b) => String.fromCharCode(b))
            .join(''));
    }
    function makeMiroPictureReq(sendResponse, token, pictureData) {
        return __awaiter(this, void 0, void 0, function* () {
            const pictureUrl = new URL(MIRO_PICTURE_URL);
            for (const key in pictureData) {
                pictureUrl.searchParams.append(key, pictureData[key]);
            }
            const pictureResponse = yield fetch(pictureUrl.href, {
                method: 'GET',
                headers: {
                    Authorization: `Bearer ${token}`,
                },
            });
            if (pictureResponse.ok) {
                try {
                    const pictureBuffer = yield pictureResponse.arrayBuffer();
                    const pictureType = pictureResponse.headers.get('Content-Type');
                    sendResponse({
                        result: `data:${pictureType};base64,${arrayBufferToBase64(pictureBuffer)}`,
                    });
                }
                catch (e) {
                    sendResponse({ result: null });
                }
            }
            else {
                sendResponse({ result: null });
            }
        });
    }
    function makeMiroProfileReq(sendResponse, token, profileData) {
        return __awaiter(this, void 0, void 0, function* () {
            const profileUrl = new URL(MIRO_PROFILE_URL);
            for (const key in profileData) {
                profileUrl.searchParams.append(key, profileData[key]);
            }
            const result = yield makeFetch('GET', profileUrl.href, token);
            sendResponse({ result: result });
        });
    }
    function makeGetBoardsReq(sendResponse, token, boardsData) {
        return __awaiter(this, void 0, void 0, function* () {
            const boardsUrl = new URL(GET_BOARDS_URL);
            for (const key in boardsData) {
                boardsUrl.searchParams.append(key, boardsData[key]);
            }
            const result = yield makeFetch('GET', boardsUrl.href, token);
            sendResponse({ result: result });
        });
    }
    function makeTrackEventReq(sendResponse, token, eventData) {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield makeFetch('POST', TRACK_EVENT_URL, token, { 'Content-Type': 'application/json' }, eventData);
            sendResponse({ result: result });
        });
    }
    function makeSearchBoardsReq(sendResponse, token, searchData) {
        return __awaiter(this, void 0, void 0, function* () {
            const boardsUrl = new URL(SEARCH_BOARDS_URL);
            for (const key in searchData) {
                boardsUrl.searchParams.append(key, searchData[key]);
            }
            const result = yield makeFetch('GET', boardsUrl.href, token);
            sendResponse({ result: result });
        });
    }
    chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
        switch (request.cmd) {
            case BACKGROUND_COMMANDS.SHOW_PAGE_ACTION:
                chrome.pageAction.show(sender.tab.id);
                break;
            case BACKGROUND_COMMANDS.GET_COOKIE:
                chrome.cookies.getAll({ domain: DOMAIN_NAME, name: 'token' }, function (result) {
                    if (result && result.length) {
                        sendResponse({ result: result[0].value });
                    }
                    else {
                        sendResponse({ result: null });
                    }
                });
                break;
            case BACKGROUND_COMMANDS.GET_GOOGLE_USER_PROFILE:
                makeGoogleUserProfileReq(sendResponse, request.token);
                break;
            case BACKGROUND_COMMANDS.GET_MIRO_TEAMS:
                makeMiroTeamsReq(sendResponse, request.token);
                break;
            case BACKGROUND_COMMANDS.GET_MIRO_PICTURE_DATA_URL:
                makeMiroPictureReq(sendResponse, request.token, request.pictureData);
                break;
            case BACKGROUND_COMMANDS.GET_MIRO_USER_PROFILE:
                makeMiroProfileReq(sendResponse, request.token, request.profileData);
                break;
            case BACKGROUND_COMMANDS.GET_BOARDS:
                makeGetBoardsReq(sendResponse, request.token, request.boardsData);
                break;
            case BACKGROUND_COMMANDS.SEARCH_BOARDS:
                makeSearchBoardsReq(sendResponse, request.token, request.searchData);
                break;
            case BACKGROUND_COMMANDS.CREATE_BOARD:
                makeCreateBoardReq(sendResponse, request.token, request.boardData);
                break;
            case BACKGROUND_COMMANDS.SHARE_BOARD:
                makeShareBoardReq(sendResponse, request.token, request.shareData);
                break;
            case BACKGROUND_COMMANDS.LOGOUT_GOOGLE:
                makeLogoutGoogleReq(sendResponse, request.token);
                chrome.cookies.remove({ url: DOMAIN, name: 'token' });
                break;
            case BACKGROUND_COMMANDS.LOGOUT_MIRO:
                makeLogoutMiroReq(sendResponse, request.token);
                break;
            case BACKGROUND_COMMANDS.LOGOUT_MIRO_TEAM:
                makeLogoutMiroTeamReq(sendResponse, request.token, request.teamId);
                break;
            case BACKGROUND_COMMANDS.TRACK_EVENT:
                makeTrackEventReq(sendResponse, request.token, request.eventData);
                break;
            default:
                sendResponse({ result: 'error', message: `Invalid 'cmd'` });
        }
        return true;
    });
    chrome.pageAction.onClicked.addListener(function (tab) {
        chrome.tabs.sendMessage(tab.id, { cmd: 'showSettings' });
    });

}());
