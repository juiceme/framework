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
    if(decryptedMessage.type === "showPreviewMessage") {
	processShowPreviewMessage(cookie, decryptedMessage.content); }
}


// Administration UI panel requires application to provide needed priviliges

function createAdminPanelUserPriviliges() {
    // at least a "view" privilige is nice-to-have, add others as you need them.
    return [ { privilige: "view", code: "v" },
	     { privilige: "preview", code: "pv" } ];
}


// Define the top button panel, always visible.
// The panel automatically contains "Logout" and "Admin Mode" buttons so no need to include those.

function createTopButtonList(cookie) {
    return [ { button: { text: "Help", callbackMessage: "getHelpMessage" },
	       priviliges: [ "view" ] },
	     { button: { text: "Preview", callbackFunction: "var myText=''; document.querySelectorAll('input').forEach(function(i){ if(i.key === 'inputfield1') { myText = i.value; }; }); sendToServerEncrypted('showPreviewMessage', { text: myText });" },
	       priviliges: [ "preview" ] } ];
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
    var mainPanel = { title: "Main UI Panel",
                     frameId: 0,
                     header: [ { text: "This is a header" }, { text: "also this" }, { text: "and this too" } ],
                     items: [ [ [ framework.createUiTextNode("sometext", "some static text") ],
                                [ framework.createUiTextArea("othertext", "some editable text", 25, 1) ],
                                [ framework.createUiMessageButton("pushme", "pushMeButtonAction", 1) ] ],
			      [ [ framework.createUiInputField("inputfield1", "this is input field", false ) ],
				[ framework.createUiInputField("inputfield2", "this is disabled input field", false, true) ] ] ] };
    var auxPanel = { title: "Aux Panel",
		     frameId: 1,
		     header: [ { text: "" }, { text: "" }, { text: "" }, { text: "" } ],
		     items: [ [ [ framework.createUiSelectionList("list1", [ "entten", "tentten", "teelikamentten" ], "tentten") ],
				[ framework.createUiSelectionList("list1", [ "fiipula", "faapula", "fot" ], "fiipula", false) ],
				[ framework.createUiSelectionList("list1", [ "eelin", "keelin", "klot" ], "klot", true, false) ],
				[ framework.createUiSelectionList("list1", [ "1", "2", "3", "4", "5", "6" ], "5") ] ] ] };
    var anotherPanel = { title: "a panel that has editable rows",
			 frameId: 2,
			 header: [ { text: "" }, { text: "" }, { text: "" }, { text: "" } ],
			 items: [ [ [ framework.createUiTextNode("t10", "Name:") ],
				    [ framework.createUiTextArea("t11", "Alfred Nussi", 25 ,1) ],
				    [ framework.createUiTextNode("t12", "Number:") ],
				    [ framework.createUiTextArea("t13", "050-555 555", 15 ,1) ] ] ],
			 newItem: [ [ framework.createUiTextNode("tnx", "Name:") ],
				    [ framework.createUiTextArea("txx", "", 25 ,1) ],
				    [ framework.createUiTextNode("txx", "Number:") ],
				    [ framework.createUiTextArea("txx", "", 15 ,1) ] ] };

    var frameList = [ { frameType: "fixedListFrame", frame: mainPanel },
		      { frameType: "fixedListFrame", frame: auxPanel },
		      { frameType: "editListFrame", frame: anotherPanel } ];
    var sendable = { type: "createUiPage",
                     content: { topButtonList: topButtonList,
                                frameList: frameList,
				buttonList: [ { id: 501, text: "OK", callbackMessage: "sendOkMessage" },
                                              { id: 502, text: "Cancel",  callbackMessage: "sendCancelMessage" } ] } };
    framework.sendCipherTextToClient(cookie, sendable);
}

function processPushMeButtonAction(cookie, data) {
    framework.servicelog("received pushMeButtonAction message");
}

function processGetHelpMessage(cookie, data) {
    framework.servicelog("received getHelpMessage message");
    var helpWebPage = new Buffer(createPreviewHtmlPage());
    sendable = { type: "showHtmlPage",
		 content: helpWebPage.toString("ascii") };
    framework.sendCipherTextToClient(cookie, sendable);
    framework.servicelog("Sent html page to client");
}

function createPreviewHtmlPage() {
    return "<!DOCTYPE html><meta charset=\"UTF-8\"><h1><u>Help Page for Framework example</u></h1><br><hr><h2><font color='red'>NOTE! You need to enable popups from the server end to see this page!</font></h2><br><br>Now if this was a real application, you could detail here the use of ethe UI model, the workflow of various buttons and fielts, etc, etc, ...<br></html>";
}

function processShowPreviewMessage(cookie, data) {
    framework.servicelog("received showPreviewMessage message, input field content is '" +
			 data.text + "'");
}


// Initialize application-specific datastorages

datastorage.initialize("mystorage", { storage: [] }, true);


// Push callbacks to framework

framework.setCallback("datastorageRead", datastorage.read);
framework.setCallback("datastorageWrite", datastorage.write);
framework.setCallback("datastorageInitialize", datastorage.initialize);
framework.setCallback("handleApplicationMessage", handleApplicationMessage);
framework.setCallback("processResetToMainState", processResetToMainState);
framework.setCallback("createAdminPanelUserPriviliges", createAdminPanelUserPriviliges);
framework.setCallback("createTopButtonList", createTopButtonList);


// Start the web interface

framework.setApplicationName("Example Application");
framework.startUiLoop();

