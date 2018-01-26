var framework = require("./framework/framework.js");
var datastorage = require('./framework/datastorage/datastorage.js');


// Application specific part starts from here

function handleApplicationMessage(cookie, decryptedMessage) {
    if(decryptedMessage.type === "resetToMain") {
        processResetToMainState(cookie, decryptedMessage.content); }
    if(decryptedMessage.type === "pushMeButtonAction") {
        processPushMeButtonAction(cookie, decryptedMessage.content); }
    if(decryptedMessage.type === "getHelpMessage") {
        processGetHelpMessage(cookie, decryptedMessage.content); }
}


// Administration UI panel requires application to provide needed priviliges

function createAdminPanelUserPriviliges() {
    return [ { privilige: "view", code: "v" },
	     { privilige: "system-admin", code: "a"} ];
}


// Define the top button panel, always visible.
// The panel automatically contains "Logout" and "Admin Mode" buttons so no need to include those.

function createTopButtonList(cookie) {
    return [ { button: { text: "Help", callbackMessage: "getHelpMessage" },
	       priviliges: [ "view" ] } ];
}


// Show up Main UI panel

function processResetToMainState(cookie, content) {
    // this shows up the first UI panel when uses login succeeds or other panels send "OK" / "Cancel" 
    framework.servicelog("User session reset to main state");
    cookie.user = datastorage.read("users").users.filter(function(u) {
	return u.username === cookie.user.username;
    })[0];
    sendMainUiPanel(cookie);
}

function sendMainUiPanel(cookie) {
    var topButtonList = framework.createTopButtons(cookie);
    var itemList = { title: "Main UI Panel",
                     frameId: 0,
                     header: [ { text: "" }, { text: "" }, { text: "" } ],
                     items: [ [ [ framework.createUiTextNode("some text", "some text") ],
                                [ framework.createUiTextNode("other text", "some text more") ],
                                [ framework.createUiButton("push me", "pushMeButtonAction", 1) ] ] ] };
    var frameList = [ { frameType: "fixedListFrame", frame: itemList } ];
    var sendable = { type: "createUiPage",
                     content: { topButtonList: topButtonList,
                                frameList: frameList } };
    framework.sendCipherTextToClient(cookie, sendable);
}

function processPushMeButtonAction(cookie, data) {
    framework.servicelog("received pushMeButtonAction message");
}

function processGetHelpMessage(cookie, data) {
    framework.servicelog("received getHelpMessage message");
}

// Initialize datastorage

datastorage.initialize("main", { main: { version: 1,
					 port: 8080,
					 siteFullUrl: "http://url.to.my.site/" } });
datastorage.initialize("users", { users: [ { username: "test",
					     hash: framework.sha1("test"),
					     password: framework.getPasswordHash("test", "test"),
					     applicationData: { priviliges: ["system-admin"] },
					     realname: "",
					     email: "",
					     phone: "" } ] }, true);


// Push callbacks to framework

framework.setCallback("datastorageRead", datastorage.read);
framework.setCallback("datastorageWrite", datastorage.write);
framework.setCallback("handleApplicationMessage", handleApplicationMessage);
framework.setCallback("processResetToMainState", processResetToMainState);
framework.setCallback("createAdminPanelUserPriviliges", createAdminPanelUserPriviliges);
framework.setCallback("createTopButtonList", createTopButtonList);


// Start the web interface

framework.startUiLoop(datastorage.read("main").main.port);

