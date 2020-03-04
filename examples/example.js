var framework = require("./framework/framework.js");
var datastorage = require('./framework/datastorage/datastorage.js');
var ui = require('./framework/uielements.js');

// Application specific part starts from here

function handleApplicationMessage(url, message) {
    console.log("URL: " +  url)
    var session = framework.refreshSessionByToken(message.token, message.data);
    if(!session) { return {result: framework.restStatusMessage("E_VERIFYSESSION")}; }
    if(url === "/api/application/pushme") {
	return processPushMeButtonAction(session, message.data); }
    if(url === "/api/application/help") {
        return processGetHelpMessage(session, message.data); }
    if(url === "/api/application/preview") {
	return processShowPreviewMessage(session, message.data); }
    if(url === "/api/application/clickedmybox") {
	return processClickedMyBox(session, message.data); }

    return {result: framework.restStatusMessage("E_UNIMPLEMENTED")};
}

function handleApplicationPoll(url, message) {
    var session = framework.refreshSessionByToken(message.token, message.data);
    if(!session) { return {result: framework.restStatusMessage("E_VERIFYSESSION")}; }
    var data = framework.decrypt(message.data, session.key);
    // application can do something with the data
    return {result: framework.restStatusMessage("E_OK")};
}

// Administration UI panel requires application to provide needed priviliges
// These can be used when restricting users for certain database operations etc.

function createAdminPanelUserPriviliges() {
    // at least a "view" privilige is nice-to-have, add others as you need them.
    return [ { privilige: "view", code: "v" },
	     { privilige: "modify", code: "m" } ];
}


// When a new user is self-created, define if some priviliges are pre-created

function createDefaultPriviliges() {
    return [ "view" ];
}


// Define the top button panel, always visible.
// The panel automatically contains "Logout" and "Admin Mode" buttons so no need to include those.

function createTopButtonList() {
    return [ { button: { text: "Help",
			 callbackFunction: "postEncrypted('/api/application/help', {}); return false;" },
	       priviliges: [ "view" ] } ];
}


// Show up Main UI panel

function processResetToMainState(session) {
    // this shows up the first UI panel when uses login succeeds or other panels send "OK" / "Cancel"
    framework.servicelog("User session reset to main state");
    return createMainUiPanel(session);
}

var listIsHidden = false;

function createMainUiPanel(session) {
    var topButtonList = ui.createTopButtons(session);
    var mainPanel = { title: "Main UI Panel",
                      frameId: 0,
		      header: [ [ [ ui.createUiHtmlCell("", "<b>This is a header</b>") ],
				  [ ui.createUiHtmlCell("", "<i>also this</i>" ) ],
				  [ ui.createUiHtmlCell("", "<u>and this too</u>" ) ] ] ],

                      items: [ [ [ ui.createUiTextNode("sometext", "some static text") ],
                                 [ ui.createUiTextArea("othertext", "some editable text", 25, 1) ],
                                 [ ui.createUiMessageButton("pushme", "/api/application/pushme", 1) ] ],
			       [ [ ui.createUiInputField("inputfield1", "this is input field", 15, false ) ],
				 [ ui.createUiInputField("inputfield2", "this is disabled input field", 15, false, true) ] ] ] };
    var auxPanel = { title: "Aux Panel",
		     frameId: 1,
		     header: [ [ [ ui.createUiHtmlCell("", "") ], [ ui.createUiHtmlCell("", "") ],
				 [ ui.createUiHtmlCell("", "") ], [ ui.createUiHtmlCell("joo", "Hide selector") ],
				 [ ui.createUiHtmlCell("", "") ] ] ],
		     items: [ [ [ ui.createUiSelectionList("list1", [ "entten", "tentten", "teelikamentten" ], "tentten") ],
				[ ui.createUiSelectionList("list1", [ "fiipula", "faapula", "fot" ], "fiipula", false) ],
				[ ui.createUiSelectionList("list1", [ "eelin", "keelin", "klot" ], "klot", true, false, false) ],
				[ ui.createUiCheckBox("check", listIsHidden, "click me if you dare!", true,
						      "postEncrypted('/api/application/clickedmybox', { state: document.getElementById(this.id).checked } );") ],
				[ ui.createUiSelectionList("list1", [ "1", "2", "3", "4", "5", "6" ], "5", true, listIsHidden) ] ] ] };
    var anotherPanel = { title: "a panel that has editable rows",
			 frameId: 2,
			 header: [ [ [ ui.createUiHtmlCell("", "") ], [ ui.createUiHtmlCell("", "") ],
				     [ ui.createUiHtmlCell("", "") ], [ ui.createUiHtmlCell("", "") ] ] ],
			 items: [ [ [ ui.createUiTextNode("t10", "Name:") ],
				    [ ui.createUiTextArea("t11", "Alfred Nussi", 25 ,1) ],
				    [ ui.createUiTextNode("t12", "Number:") ],
				    [ ui.createUiTextArea("t13", "050-555 555", 15 ,1) ] ] ],
			 newItem: [ [ ui.createUiTextNode("tnx", "Name:") ],
				    [ ui.createUiTextArea("txx", "", 25 ,1) ],
				    [ ui.createUiTextNode("txx", "Number:") ],
				    [ ui.createUiTextArea("txx", "", 15 ,1) ] ] };

    var frameList = [ { frameType: "fixedListFrame", frame: mainPanel },
		      { frameType: "fixedListFrame", frame: auxPanel },
		      { frameType: "editListFrame", frame: anotherPanel } ];
    var data = { type: "createUiPage",
		 content: { topButtonList: topButtonList,
                            frameList: frameList,
			    buttonList: [ { id: 501,
					    text: ui.getLanguageText(session, "BUTTON_OK"),
					    callbackMessage: "sendOkMessage" },
                                          { id: 502,
					    text: ui.getLanguageText(session, "BUTTON_CANCEL"),
					    callbackMessage: "sendCancelMessage" } ] } };
    return { result: framework.restStatusMessage("E_OK"),
	     message: "Login OK",
	     type: "T_UIWINDOWREQUEST",
	     data: framework.encrypt(data, session.key) };
}

function processPushMeButtonAction(session, data) {
    var serialTokenData = framework.decrypt(data, session.key);
    framework.servicelog("received pushMeButtonAction message, button ID: " + serialTokenData.data.buttonId);
    return { result: framework.restStatusMessage("E_OK") };
}

function processClickedMyBox(session, data) {
    var serialTokenData = framework.decrypt(data, session.key);
    framework.servicelog("received clickedMyBox message, state: " + serialTokenData.data.state);
    listIsHidden = serialTokenData.data.state;
    return processResetToMainState(session);
}

function processGetHelpMessage(session, data) {
    framework.servicelog("received getHelpMessage message");
    var helpWebPage = Buffer.from(createHelpHtmlPage());
    var data = { type: "showHtmlPage",
		 content: helpWebPage.toString("ascii") };
    return { result: framework.restStatusMessage("E_OK"),
	     message: "Show help message",
	     type: "T_UINEWDOCUMENTWINDOWREQUEST",
	     data: framework.encrypt(data, session.key) };
}

function createHelpHtmlPage() {
    return "<!DOCTYPE html><meta charset=\"UTF-8\"><h1><u>Help Page for Framework example</u></h1><br><hr><h2><font color='red'>NOTE! You need to enable popups from the server end to see this page!</font></h2><br><br>Now if this was a real application, you could detail here the use of ethe UI model, the workflow of various buttons and fielts, etc, etc, ...<br></html>";
}

function processShowPreviewMessage(session, data) {
    framework.servicelog("received showPreviewMessage message, input field content is '" + data.text + "'");
}


// Initialize application-specific datastorages

datastorage.initialize("mystorage", { storage: [],
				      priviliges: { read: ["view"],
						    append: ["modify"],
						    modify: ["modify"] } }, true);


// Push callbacks to framework

framework.setCallback("datastorageRead", datastorage.read);
framework.setCallback("datastorageWrite", datastorage.write);
framework.setCallback("datastorageInitialize", datastorage.initialize);
framework.setCallback("handleApplicationMessage", handleApplicationMessage);
framework.setCallback("handleApplicationPoll", handleApplicationPoll);
framework.setCallback("processResetToMainState", processResetToMainState);
framework.setCallback("createAdminPanelUserPriviliges", createAdminPanelUserPriviliges);
framework.setCallback("createDefaultPriviliges", createDefaultPriviliges);
framework.setCallback("createTopButtonList", createTopButtonList);


// Start the web interface

framework.setApplicationName("Example Application");
framework.startUiLoop();

