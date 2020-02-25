var http = require("http");
var fs = require("fs");
var email = require("emailjs/email");
var Aes = require('./crypto/aes.js');
Aes.Ctr = require('./crypto/aes-ctr.js');
var sha1 = require('./crypto/sha1.js');
var ui = require('./uielements.js');

var listenPort = 0;
var applicationName = "<name not set>";
var globalSalt = sha1.hash(JSON.stringify(new Date().getTime()));

function servicelog(s) {
    console.log((new Date()) + " --- " + s);
}

function getClientVariables() {
    return "var LISTEN_PORT = " + listenPort + ";\n";
}

function setApplicationName(name) {
    applicationName = name;
}

function encrypt(data, key) {
    return Aes.Ctr.encrypt(JSON.stringify(data), key, 128);
}

function decrypt(data, key) {
    return JSON.parse(Aes.Ctr.decrypt(data, key, 128));
}

function restStatusMessage(status) {
    var text = "";
    if(status === "E_UNIMPLEMENTED") { text = "Feature not implemented yet"; }
    if(status === "E_UNSUPPORTED") { text = "Unsupported method"; }
    if(status === "E_FORMAT") { text = "Invalid JSON message"; }
    if(status === "E_OK") { text = "Success"; }
    if(status === "E_USER") { text = "Invalid user login attempt"; }
    if(status === "E_CREATESESSION") { text = "Cannot create user session"; }
    if(status === "E_VERIFYSESSION") { text = "Cannot verify user session"; }
    if(status === "E_VERIFY") { text = "Cannot verify message"; }
    if(status === "E_UNKNOWNWINDOW") { text = "Cannot create unknown window"; }
    if(status === "E_INTERNALERROR") { text = "Server internal error"; }
    if(status === "E_PRIVILIGE") { text = "User does not have privilige"; }
    return {result:status, text:text};
}

var webServer = http.createServer(function(request, response){    
    request.on('data', function(textBuffer) {
	try {
	    if(request.method === "POST") {
//		servicelog("---------------> " + textBuffer)
//		servicelog("---------------> " + request.url)
		var postData = JSON.parse(textBuffer.toString().replace(/'/g, '"'));
		res = handleRestMessage(request.url, postData);
		response.writeHeader(200, { "Content-Type": "text/html",
					    "X-Frame-Options": "deny",
					    "X-XSS-Protection": "1; mode=block",
					    "X-Content-Type-Options": "nosniff" });
		response.write(JSON.stringify(res, null, 4));
		response.end();
	    }
	} catch(err) {
	    servicelog("Received illegal api call: " + err);
	    response.writeHeader(200, { "Content-Type": "text/html",
					"X-Frame-Options": "deny",
					"X-XSS-Protection": "1; mode=block",
					"X-Content-Type-Options": "nosniff" });
	    response.write(JSON.stringify({result: restStatusMessage("E_FORMAT")}, null, 4))
	    response.end();
	}
    });
    if(request.method === "GET") {
	// api calls do not request client    
	var clienthead = fs.readFileSync("./framework/clienthead", "utf8");
	var variables = getClientVariables();
	var clientbody = fs.readFileSync("./framework/client.js", "utf8");
	var aesjs = fs.readFileSync("./framework/crypto/aes.js", "utf8");
	var aesctrjs = fs.readFileSync("./framework/crypto/aes-ctr.js", "utf8");
	var sha1js = fs.readFileSync("./framework/crypto/sha1.js", "utf8");
	var sendable = clienthead + variables + clientbody + aesjs + aesctrjs + sha1js + "</script></body></html>";
	response.writeHeader(200, { "Content-Type": "text/html",
                                    "X-Frame-Options": "deny",
                                    "X-XSS-Protection": "1; mode=block",
                                    "X-Content-Type-Options": "nosniff" });
	response.write(sendable);
	response.end();
	servicelog("Respond with client to: " + JSON.stringify(request.headers));
    }
    if(request.method === "PUT") {
	response.writeHeader(200, { "Content-Type": "text/html",
                                    "X-Frame-Options": "deny",
                                    "X-XSS-Protection": "1; mode=block",
                                    "X-Content-Type-Options": "nosniff" });
	response.write(JSON.stringify({result: restStatusMessage("E_UNSUPPORTED")}, null, 4))
	response.end();
	servicelog("Respond with client to: " + JSON.stringify(request.headers));
    }
});

function handleRestMessage(url, postData) {
//    servicelog('got data: ' + JSON.stringify(postData));
//    servicelog("got request: " + JSON.stringify(url));
    
    if(url === "/") {
	return {result: restStatusMessage("E_FORMAT")};
    }

    if(url.split("/")[2] === "start") {
	return processClientStarted("login");
    }

    if(url.split("/")[2] === "login") {
	return processUserLogin(postData);
    }
    
    if(url.split("/")[2] === "logout") {
	return processUserLogout(postData);
    }
    
    if(url.split("/")[2] === "passwordrecovery") {
	return processCreateOrModifyAccount(postData);
    }
    
    if(url.split("/")[2] === "sendpasswordemail") {
	return processAccountRequestMessage(postData);
    }
    
    if(url.split("/")[2] === "validateaccount") {
	return processValidateAccountMessage(postData);
    }

    if(url.split("/")[2] === "useraccountchange") {
	if(url.split("/")[3] === "loggedin") {
	    return processUserAccountChangeMessage(postData, true);
	}
	return processUserAccountChangeMessage(postData, false);
    }

    if(url.split("/")[2] === "adminpanel") {
	return processAdminPanelRequest(postData);
    }

    if(url.split("/")[2] === "adminchange") {
	return processAdminAccountChangeMessage(postData);
    }

    if(url.split("/")[2] === "changepassword") {
	return processChangeUserPasswordMessage(postData);
    }
    
    if(url.split("/")[2] === "useraccountpanel") {
	return processUserAccountRequest(postData);
    }
    
    if(url.split("/")[2] === "xyzzy") {
	servicelog('got data: ' + JSON.stringify(postData));
	return Rest(postData);
    }
    
    if(url.split("/")[2] === "window") {    
	if(url.split("/")[3] === "0") {
	    var session = refreshSessionByToken(postData.token, postData.data);
	    if(!session) {
		servicelog("Window message session verification failed");
		return {result: restStatusMessage("E_VERIFYSESSION")};
	    }
	    return createMainWindow(session);
	} else {
	    // if not handled here, defer to application
	    return runCallbackByName("handleApplicationMessage", url, postData)
	}
    }

    // call that are not caught by framework are handled by application
    return runCallbackByName("handleApplicationMessage", url, postData);
}

function processUserLogin(data) {
    if(typeof this.counter == 'undefined' ) {
	this.counter = 0;
    }
    this.counter++;
    if(!data.username) {
	servicelog("Illegal user login message");
	return processClientStarted("login");
    } else {
	var user = getUserByHashedUserName(data.username);
	if(user === undefined) {
	    servicelog("Unknown user login attempt");
	    return processClientStarted("login");
	} else {
	    var aesKey = user.password;
	    servicelog("User " + user.username + " logging in");
	    var sessionKey = getNewSessionKey();
	    var token = sha1.hash(JSON.stringify(new Date().getTime()) +
				  this.counter).slice(0, 12);
	    var serial = Math.floor(Math.random() * 1000000) + 10;
	    var serialKey = Aes.Ctr.encrypt(JSON.stringify({ serial: serial,
							     key: sessionKey }), aesKey, 128);
	    if(createSession(sessionKey, user.username, token, serial)) {
		return { result: restStatusMessage("E_OK"),
			 message: "Logging in",
			 type: "T_LOGIN",
			 token: token,
			 serialKey: serialKey };
	    } else {
		return {result: restStatusMessage("E_CREATESESSION")};
	    }
	}
    }
}

function processUserLogout(data) {
    var session = refreshSessionByToken(data.token, data.data);
    if(!session) {
	servicelog("Incoming message verification failed");
	return processClientStarted("login");
    }
    deleteSessionByToken(data.token, data.data);
    return processClientStarted("login");
}

function createMainWindow(session) {
    if(getUserPriviliges(getUserByUsername(session.username)).length === 0) {
	// for unpriviliged login, only send logout button and nothing more
	data = { type: "unpriviligedLogin",
		 content: { topButtonList: [{ id: 100,
					      text: "Log Out",
					      callbackFunction: "sessionKey=''; postData('/api/start', {}); return false;" }]}};
	servicelog("Sending unpriviligedLogin info to client");
	return { result: restStatusMessage("E_OK"),
		 message: "Login OK",
		 type: "T_UIWINDOWREQUEST",
		 token: session.token,
		 data: Aes.Ctr.encrypt(JSON.stringify(data), session.key, 128) };
    } else {
	// Login succeeds, start the UI engine
	return runCallbackByName("processResetToMainState", session);
    }
}

function processClientStarted(message) {
    servicelog("Sending initial login view to client");
    var items = [];
    items.push([ [ ui.createUiTextNode("username", ui.getLanguageText(null, "TERM_USERNAME") + ":") ],
		 [ ui.createUiInputField("userNameInput", "", 15, false) ] ]);
    items.push([ [ ui.createUiTextNode("password", ui.getLanguageText(null, "TERM_PASSWORD") + ":") ],
		 [ ui.createUiInputField("passwordInput", "", 15, true) ] ]);
    var itemList = { title: ui.getLanguageText(null, "PROMPT_LOGIN"),
                     frameId: 0,
		     header: [ [ [ ui.createUiHtmlCell("", "") ], [ ui.createUiHtmlCell("", "") ] ] ],
		     rowNumbers: false,
                     items: items };
    var frameList = [ { frameType: "fixedListFrame", frame: itemList } ];
    var buttonList = [ { id: 501,
			 text: ui.getLanguageText(null, "BUTTON_LOGIN"),
			 callbackFunction: "var username=''; var password=''; document.querySelectorAll('input').forEach(function(i){ if(i.key === 'userNameInput') { username = i.value; }; if(i.key === 'passwordInput') { password = i.value; }; }); sessionKey=Sha1.hash(password + Sha1.hash(username).slice(0,4)); postData('/api/login', {username : Sha1.hash(username)}); return false;" } ];
    if(runCallbackByName("datastorageRead", "main").main.emailVerification) {
	buttonList.push({ id: 502,
			  text: ui.getLanguageText(null, "BUTTON_NEWACCOUNT"),
			  callbackFunction: "sessionKey=''; postData('/api/passwordrecovery', {}); return false;" });
    }
    return { result: restStatusMessage("E_OK"),
	     message: message,
	     type: "T_LOGINUI",
	     data: { type: "createUiPage",
		      content: { frameList: frameList,
				 buttonList: buttonList }}};
}

function processCreateOrModifyAccount(data) {
    servicelog("Sending create/modify view to client");
    var items = [];
    items.push([ [ ui.createUiTextNode("email", ui.getLanguageText(null, "TERM_EMAIL") + ":" ) ],
		 [ ui.createUiInputField("emailInput", "", 15, false) ],
		 [ ui.createUiFunctionButton(ui.getLanguageText(null, "BUTTON_SENDEMAIL"), "var email=''; document.querySelectorAll('input').forEach(function(i){ if(i.key === 'emailInput') { email = i.value; }; }); postData('/api/sendpasswordemail', {email:email}); return false;") ] ]);
    items.push([ [ ui.createUiTextNode("verification", ui.getLanguageText(null, "TERM_VERIFICATIONCODE") + ":" ) ],
		 [ ui.createUiInputField("verificationInput", "", 15, false) ],
		 [ ui.createUiFunctionButton(ui.getLanguageText(null, "BUTTON_VALIDATEACCOUNT"), "var code=''; document.querySelectorAll('input').forEach(function(i){ if(i.key === 'verificationInput') { code = i.value; }; }); sessionKey = code.slice(8,24); postData('/api/validateaccount', { email: code.slice(0,8), challenge: Aes.Ctr.encrypt('clientValidating', sessionKey, 128) });") ] ]);
    var itemList = { title: ui.getLanguageText(null, "PROMPT_CHANGEACCOUNT"),
                     frameId: 0,
		     header: [ [ [ ui.createUiHtmlCell("", "") ], [ ui.createUiHtmlCell("", "") ], [ ui.createUiHtmlCell("", "") ] ] ],
		     rowNumbers: false,
                     items: items };
    var frameList = [ { frameType: "fixedListFrame", frame: itemList } ];
    return { result: restStatusMessage("E_OK"),
	     message: "create/modify",
	     type: "T_VERIFYUI",
	     data: { type: "createUiPage",
                     content: { frameList: frameList,
				buttonList: [ { id: 501,
						text: ui.getLanguageText(null, "BUTTON_CANCEL"),
						callbackFunction: "sessionKey=''; postData('/api/start', {}); return false;" }]}}};
}

function processAccountRequestMessage(data) {
    servicelog("Request for email verification: [" + data.email + "]");
    if(data.email.length === 0) {
	return processCreateOrModifyAccount(data);
    }
    sendVerificationEmail(data.email);
    // send login panel
    return processClientStarted("sent email");
}

function processValidateAccountMessage(data) {
    if(!data.email || !data.challenge) {
	servicelog("Illegal validate account message");
	return restStatusMessage("E_VERIFY");
    } else {
    	servicelog("Validation code: " + JSON.stringify(data));
	var request = validatePendingRequest(data.email.toString());
	if(request === false) {
	    servicelog("Failed to validate pending request");
	    return restStatusMessage("E_VERIFY");
	}
	if(Aes.Ctr.decrypt(data.challenge, request.token.key, 128) !== "clientValidating") {
	    servicelog("Failed to validate code");
	    return restStatusMessage("E_VERIFY");
	}
	var newAccount = { checksum: request.checksum,
			   isNewAccount: request.isNewAccount,
			   showAccountDeletePanel: false,
			   email: request.email,
			   username: request.username };
	if(request.isNewAccount) {
	    newAccount.realname = "";
	    newAccount.phone = "";
	    newAccount.language = runCallbackByName("datastorageRead", "main").main.defaultLanguage;
	} else {
	    var user = getUserByEmail(request.email);
	    newAccount.realname = user.realname;
	    newAccount.phone = user.phone;
	    newAccount.language = user.language;
	}
	return sendUserAccountModificationDialog(newAccount, request.token.key, false);
    }    
}

function sendUserAccountModificationDialog(account, key, loggedin) {
    var title = "";
    var configurationItems = [];
    configurationItems.push([ [ ui.createUiTextNode("email", ui.getLanguageText(null, "TERM_EMAIL") + ":") ],
			      [ ui.createUiInputField("emailInput", account.email, 15, false) ] ]);
    if(account.isNewAccount) {
	title = ui.getLanguageText(null, "PROMPT_CREATENEWACCOUNT");
	configurationItems.push([ [ ui.createUiTextNode("username", ui.getLanguageText(null, "TERM_USERNAME") + ":") ],
				  [ ui.createUiInputField("usernameInput", account.username, 15, false) ] ]);
    } else {
	title = ui.getLanguageText(null, "PROMPT_MODIFYOLDACCOUNT");
	configurationItems.push([ [ ui.createUiTextNode("username", ui.getLanguageText(null, "TERM_USERNAME") + ":") ],
				  [ ui.createUiInputField("usernameInput", account.username, 15, false, true) ] ]);
    }
    configurationItems.push([ [ ui.createUiTextNode("realname", ui.getLanguageText(null, "TERM_REALNAME")) ],
			      [ ui.createUiInputField("realnameInput", account.realname, 15, false) ] ]);
    configurationItems.push([ [ ui.createUiTextNode("phone", ui.getLanguageText(null, "TERM_PHONE")) ],
			      [ ui.createUiInputField("phoneInput", account.phone, 15, false) ] ]);
    configurationItems.push([ [ ui.createUiTextNode("language", ui.getLanguageText(null, "TERM_LANGUAGE")) ],
			      [ ui.createUiSelectionList("languageInput", runCallbackByName("datastorageRead" ,"language").languages, account.language, true, false, false) ] ]);
    configurationItems.push([ [ ui.createUiTextNode("password1", ui.getLanguageText(null, "TERM_PASSWORD")) ],
			      [ ui.createUiInputField("passwordInput1", "", 15, true) ] ]);
    configurationItems.push([ [ ui.createUiTextNode("password2", ui.getLanguageText(null, "TERM_REPEATPASSWORD")) ],
			      [ ui.createUiInputField("passwordInput2", "", 15, true) ] ]);
    var configurationItemList = { title: title,
				  frameId: 0,
				  header: [ [ [ ui.createUiHtmlCell("", "") ], [ ui.createUiHtmlCell("", "") ] ] ],
				  rowNumbers: false,
				  items: configurationItems };
    var frameList = [ { frameType: "fixedListFrame", frame: configurationItemList } ];
    if(account.showAccountDeletePanel) {
	var deleteAccountItemList = { title: ui.getLanguageText(null, "PROMPT_DELETEACCOUNT"),
				      frameId: 1,
				      header: [ [ [ ui.createUiHtmlCell("", "") ] ] ],
				      rowNumbers: false,
				      items: [ [ [ ui.createUiFunctionButton(ui.getLanguageText(null, "BUTTON_DELETEACCOUNT"), "if(confirm('" + ui.getLanguageText(null, 'PROMPT_CONFIRMDELETEACCOUNT') + "')) { sendToServerEncrypted('deleteAccountMessage', { }); }") ] ] ] };
	frameList.push({ frameType: "fixedListFrame", frame: deleteAccountItemList });
    }
    if(loggedin) {
	var callbackFunction = "var userData=[{ key:'isNewAccount', value:" + account.isNewAccount + " }]; document.querySelectorAll('input').forEach(function(i){ if(i.key != undefined) { userData.push({ key:i.key, value:i.value } ); } }); document.querySelectorAll('select').forEach(function(i){ if(i.key != undefined) { userData.push({ key:i.key, selected:i.options[i.selectedIndex].item } ); } }); postEncrypted('/api/useraccountchange/loggedin', { checksum: '" + account.checksum + "', data: userData }); return false;"
    } else {
	var callbackFunction = "var userData=[{ key:'isNewAccount', value:" + account.isNewAccount + " }]; document.querySelectorAll('input').forEach(function(i){ if(i.key != undefined) { userData.push({ key:i.key, value:i.value } ); } }); document.querySelectorAll('select').forEach(function(i){ if(i.key != undefined) { userData.push({ key:i.key, selected:i.options[i.selectedIndex].item } ); } }); postData('/api/useraccountchange', { checksum: '" + account.checksum + "', data: Aes.Ctr.encrypt(JSON.stringify(userData), sessionKey, 128) }); return false;"
    }
    
    var data = { type: "createUiPage",
                 content: { frameList: frameList,
			    buttonList: [ { id: 501,
					    text: ui.getLanguageText(null, "BUTTON_CANCEL"),
					    callbackFunction: "sessionKey=''; postData('/api/start', {}); return false;" },
					  { id: 502,
					    text: ui.getLanguageText(null, "BUTTON_OK"),
					    callbackFunction: callbackFunction }]}};
    return { result: restStatusMessage("E_OK"),
	     message: "Change Account",
	     type: "T_USERMODIFICATIONUI",
	     data: Aes.Ctr.encrypt(JSON.stringify(data), key, 128) };
}

function createLoggedinUserAccountChange(session) {
    // user account modification fakes an email verification sequence
    var user = getUserByUsername(session.username);
    var request = createPendingRequest(user.email, true);
    request = validatePendingRequest(request.token.mail);
    request = getValidatedPendingRequest(request.checksum);
    var account = { checksum: request.checksum,
		    isNewAccount: false,
		    username: user.username,
		    email: user.email,
		    realname: user.realname,
		    phone: user.phone,
		    language: user.language };
    return account;
}

function processUserAccountChangeMessage(data, loggedin) {
    if(!data) {
	servicelog("User account change contains no data.");
	return {result: restStatusMessage("E_FORMAT")};
    }
    var accountData;
    var checkSum;

    if(loggedin) {
	var session = getSessionByToken(data.token);
	if(!session) {
	    servicelog("Cannot determine session in User account change.");
	    return {result: restStatusMessage("E_FORMAT")};
	}
	accountData = JSON.parse(Aes.Ctr.decrypt(data.data, session.key, 128));
	var request = getValidatedPendingRequest(accountData.data.checksum);
	if(!request) {
	    servicelog("Cannot get a validated pending request");
	    return {result: restStatusMessage("E_VERIFY")};
	}
	checkSum = accountData.data.checksum;
	accountData = accountData.data.data;	
    } else {  
	var request = getValidatedPendingRequest(data.checksum);
	if(!request) {
	    servicelog("Cannot get a validated pending request");
	    return {result: restStatusMessage("E_VERIFY")};
	}
	accountData = JSON.parse(Aes.Ctr.decrypt(data.data, request.token.key, 128));
	checkSum = data.checksum;
    }
    var account = { checksum: checkSum,
		    isNewAccount: request.isNewAccount,
		    email: findObjectByKey(accountData, "key", "emailInput").value,
		    realname: findObjectByKey(accountData, "key", "realnameInput").value,
		    phone: findObjectByKey(accountData, "key", "phoneInput").value,
		    language: findObjectByKey(accountData, "key", "languageInput").selected };
    if(findObjectByKey(accountData, "key", "usernameInput").value.length === 0) {
	account.username = "";
	servicelog("User attempted to create empty username");
	return sendUserAccountModificationDialog(account, request.token.key, loggedin);
    }
    if(request.isNewAccount && (getUserByUsername(findObjectByKey(accountData, "key", "usernameInput").value) !== false)) {
	account.username = "";
	servicelog("User attempted to create an existing username");
	return sendUserAccountModificationDialog(account, request.token.key, loggedin);
    } else {
	account.username = findObjectByKey(accountData, "key", "usernameInput").value;
    }
    if(findObjectByKey(accountData, "key", "passwordInput1").value !==
       findObjectByKey(accountData, "key", "passwordInput2").value) {
	servicelog("Password mismatch in account change dialog");
	return sendUserAccountModificationDialog(account, request.token.key, loggedin);
    }
    account.password = findObjectByKey(accountData, "key", "passwordInput1").value;
    changeUserAccount(account);
    sendConfirmationEmails(account);
    return processClientStarted("Account Saved");
}

function findObjectByKey(array, key, value) {
    for (var i = 0; i < array.length; i++) {
        if (array[i][key] === value) {
            return array[i];
        }
    }
    return null;
}

function createPriviligeList() {
    var priviligeList = runCallbackByName("createAdminPanelUserPriviliges");
    priviligeList.push({ privilige: "system-admin", code: "a"});
    return priviligeList;
}

function sendAdminDialog(session) {
    servicelog("User " + session.username + " requests Sytem Administration priviliges");
    if(userHasPrivilige("system-admin", getUserByUsername(session.username))) {
	servicelog("Granting Sytem Administration priviliges to user " + session.username);
	var topButtonList =  ui.createTopButtons(session, [], true);
	var items = [];
	var priviligeList = createPriviligeList();
	runCallbackByName("datastorageRead", "users").users.forEach(function(u) {
	    var userPriviliges = [];
	    priviligeList.forEach(function(p) {
		userPriviliges.push(ui.createUiCheckBox(p.privilige, userHasPrivilige(p.privilige, u), p.code));
	    });
	    items.push([ [ ui.createUiTextNode("username", u.username) ],
			 [ ui.createUiInputField("realname", u.realname, 15) ],
			 [ ui.createUiInputField("email", u.email, 20) ],
			 [ ui.createUiInputField("phone", u.phone, 10) ],
			 [ ui.createUiSelectionList("language", runCallbackByName("datastorageRead" ,"language").
						    languages, u.language, true, false, false) ],
			 userPriviliges,
		         [ ui.createUiMessageButton("Change", "/api/changepassword/", u.username),
			   ui.createUiInputField("password", "", 10, true) ] ] )
	});
	var emptyPriviligeList = [];
	priviligeList.forEach(function(p) {
	    emptyPriviligeList.push(ui.createUiCheckBox(p.privilige, false, p.code));
	});
        var priviligeCodes = "";
        createPriviligeList().forEach(function(p) {
            priviligeCodes = priviligeCodes + p.code + " / ";
        });
        priviligeCodes = priviligeCodes.slice(0, priviligeCodes.length-3);
	var userListPanel = { title: ui.getLanguageText(session, "PROMPT_USERADMIN"),
			      frameId: 0,
			      header: [ [ [ ui.createUiHtmlCell("", "") ],
					  [ ui.createUiHtmlCell("", ui.getLanguageText(session, "TERM_USERNAME")) ],
					  [ ui.createUiHtmlCell("", ui.getLanguageText(session, "TERM_REALNAME")) ],
					  [ ui.createUiHtmlCell("", ui.getLanguageText(session, "TERM_EMAIL")) ],
					  [ ui.createUiHtmlCell("", ui.getLanguageText(session, "TERM_PHONE")) ],
					  [ ui.createUiHtmlCell("", ui.getLanguageText(session, "TERM_LANGUAGE")) ],
					  [ ui.createUiHtmlCell("", priviligeCodes) ],
					  [ ui.createUiHtmlCell("", ui.getLanguageText(session, "BUTTON_CHANGEPASSWORD")) ] ] ],
			      items: items,
			      newItem: [ [ ui.createUiInputField("username", "<username>", 10) ],
					 [ ui.createUiInputField("realname", "<realname>", 15) ],
					 [ ui.createUiInputField("email", "<email>", 20) ],
					 [ ui.createUiInputField("phone", "<phone>", 10) ],
					 [ ui.createUiSelectionList("language", runCallbackByName("datastorageRead" ,"language").
								    languages, runCallbackByName("datastorageRead", "main").
								    main.defaultLanguage, true, false, false) ],
					 emptyPriviligeList,
					 [ ui.createUiTextNode("password", "") ] ] };
	var email = runCallbackByName("datastorageRead", "email");
	var emailEnabled = runCallbackByName("datastorageRead", "main").main.emailVerification;
	var emailConfigPanel = { title: ui.getLanguageText(session, "PROMPT_EMAILADMIN"),
				 frameId: 1,
				 header: [ [ [ ui.createUiHtmlCell("", "") ], [ ui.createUiHtmlCell("", "") ] ] ],
				 items: [ [ [ ui.createUiTextNode("email_enabled", ui.getLanguageText(session, "TERM_ENABLED")) ],
					    [ ui.createUiCheckBox("email_enabled", emailEnabled, "enabled")] ],
					  [ [ ui.createUiTextNode("mailserver", ui.getLanguageText(session, "TERM_MAILSERVER")) ],
					    [ ui.createUiInputField("mailserver", email.host, 15) ] ],
					  [ [ ui.createUiTextNode("username", ui.getLanguageText(session, "TERM_USERNAME")) ],
					    [ ui.createUiInputField("username", email.user, 15) ] ],
					  [ [ ui.createUiTextNode("sender", ui.getLanguageText(session, "TERM_SENDERADDRESS")) ],
					    [ ui.createUiInputField("sender", email.sender, 15) ] ],
					  [ [ ui.createUiTextNode("password", ui.getLanguageText(session, "TERM_PASSWORD")) ],
					    [ ui.createUiInputField("password", email.password, 15, true) ] ],
					  [ [ ui.createUiTextNode("use_ssl", ui.getLanguageText(session, "TERM_USESSL")) ],
					    [ ui.createUiCheckBox("use_ssl", email.ssl, "use ssl") ] ],
					  [ [ ui.createUiTextNode("blindly_trust", ui.getLanguageText(session, "TERM_BLINDLYTRUST")) ],
					    [ ui.createUiCheckBox("blindly_trust", email.blindlyTrust, "blindly trust") ] ] ] };
					
	var frameList = [ { frameType: "editListFrame", frame: userListPanel },
			  { frameType: "fixedListFrame", frame: emailConfigPanel } ];
	var data = { type: "createUiPage",
		     content: { topButtonList: topButtonList,
				frameList: frameList,
				buttonList: [ { id: 501,
						text: ui.getLanguageText(null, "BUTTON_OK"),
						callbackUrl: "/api/adminchange/" },
					      { id: 502,
						text: ui.getLanguageText(null, "BUTTON_CANCEL"),
						callbackFunction: "postEncrypted('/api/window/0', {}); return false;" } ] } };
	return { result: restStatusMessage("E_OK"),
		 message: "Admin Panel",
		 type: "T_UIWINDOWREQUEST",
		 data: Aes.Ctr.encrypt(JSON.stringify(data), session.key, 128) };
    } else {
	servicelog("User " + session.username + " does not have Sytem Administration priviliges!");
	return { result: restStatusMessage("E_UNIMPLEMENTED") }
    }	
}

function processAdminPanelRequest(data) {
    var session = refreshSessionByToken(data.token, data.data);
    if(!session) {
	servicelog("Incoming message verification failed");
	return {result: restStatusMessage("E_VERIFYSESSION")};
    }
    var user = getUserByUsername(session.username);
    if(!user) {
	return {result: restStatusMessage("E_USER")};
    }
    if(!userHasPrivilige("system-admin", user)) {
	return {result: restStatusMessage("E_PRIVILIGE")};
    }
    return sendAdminDialog(session)
}

function processAdminAccountChangeMessage(data) {
    var session = refreshSessionByToken(data.token, data.data);
    if(!session) {
	servicelog("Incoming message verification failed");
	return {result: restStatusMessage("E_VERIFYSESSION")};
    }
    if(!userHasPrivilige("system-admin", getUserByUsername(session.username))) {
	servicelog("User has no administration priviliges");
	return {result: restStatusMessage("E_PRIVILIGE")};
    }
    var accountData = JSON.parse(Aes.Ctr.decrypt(data.data, session.key, 128)).data;
    var userList = extractUserListFromInputData(accountData);
    var emailSettings = extractEmailSettingsFromInputData(accountData);
    if(userList === null) {
	// see if this is OK?
	servicelog("------------------------------??")
	return sendAdminDialog(session)
    }
    var newUsers = [];
    var oldUsers = runCallbackByName("datastorageRead", "users").users;
    userList.forEach(function(n) {
	var flag = true;
	oldUsers.forEach(function(u) {
	    if(n.username === u.username) {
		flag = false;
		n.password = u.password;
		newUsers.push(n);
	    }
	});
	if(flag) {
	    n.password = "";
	    newUsers.push(n);
	}
    });
    if(runCallbackByName("datastorageWrite", "users", { users: newUsers }) === false) {
	servicelog("User database write failed");
    }
    var main = runCallbackByName("datastorageRead", "main").main;
    main.emailVerification = emailSettings.enabled;
    if(runCallbackByName("datastorageWrite", "main", { main: main }) === false) {
	servicelog("Main database write failed");
    }
    var emailPassword = runCallbackByName("datastorageRead", "email").password;
    var newEmailSettings = { host: emailSettings.host,
			     user: emailSettings.user,
			     sender: emailSettings.sender,
			     password: emailSettings.password,
			     ssl: emailSettings.ssl,
			     blindlyTrust: emailSettings.blindlyTrust };
    if(newEmailSettings.password === "") {
	newEmailSettings.password = emailPassword;
    }
    if(runCallbackByName("datastorageWrite", "email", newEmailSettings) === false) {
	servicelog("Email database write failed");
    }
    servicelog("Updated User database.");
    return createMainWindow(session);
}

function processChangeUserPasswordMessage(data) {
    var session = refreshSessionByToken(data.token, data.data);
    if(!session) {
	servicelog("Incoming message verification failed");
	return {result: restStatusMessage("E_VERIFYSESSION")};
    }
    if(!userHasPrivilige("system-admin", getUserByUsername(session.username))) {
	servicelog("User has no administration priviliges");
	return {result: restStatusMessage("E_PRIVILIGE")};
    }
    var accountData = JSON.parse(Aes.Ctr.decrypt(data.data, session.key, 128)).data;
    var passwordChange = extractPasswordChangeFromInputData(accountData);
    if(passwordChange === null) {
	servicelog("--------------xxxxxxxxxxxxx")
	return sendAdminDialog(session)
    }
    var newUsers = [];
    runCallbackByName("datastorageRead", "users").users.forEach(function(u) {
	if(u.username !== passwordChange.userName) {
	    newUsers.push(u);
	} else {
	    newUsers.push({ applicationData: u.applicationData,
			    username: u.username,
			    hash: u.hash,
			    realname: u.realname,
			    email: u.email,
			    phone: u.phone,
			    language: u.language,
			    password: passwordChange.password });
	}
    });
    if(runCallbackByName("datastorageWrite", "users", { users: newUsers }) === false) {
	servicelog("User database write failed");
	return {result: restStatusMessage("E_INTERNALERROR")};
    } else {
	servicelog("Updated password of user [" + JSON.stringify(passwordChange.userName) + "]");
	return sendAdminDialog(session);
    }
}

function extractUserListFromInputData(data) {
    if(data.items === undefined) {
	servicelog("inputData does not contain items");
	return null;
    }
    var userList = [];
    data.items[0].frame.forEach(function(u) {
	var user = { applicationData: { priviliges: [] } };
	u.forEach(function(row) {
	    if(row.length === 1) {
		if(row[0].key === "username") {
		    if(row[0].text !== undefined) {
			user.username = row[0].text;
			user.hash = sha1.hash(row[0].text);
		    }
		    if(row[0].value !== undefined) {
			user.username = row[0].value;
			user.hash = sha1.hash(row[0].value);
		    }
		}
		if(row[0].key === "realname") { user.realname = row[0].value; }
		if(row[0].key === "email") { user.email = row[0].value; }
		if(row[0].key === "phone") { user.phone = row[0].value; }
		if(row[0].key === "language") { user.language = row[0].selected; }
	    } else {
		var priviligeList = createPriviligeList().map(function(p) {
		    return p.privilige;
		}); 
	    	row.forEach(function(item) {
		    priviligeList.forEach(function(p) {
			if(item.key === p) {
			    if(item.checked) {
				user.applicationData.priviliges.push(p);
			    }
			}
		    });
		});
	    }
	});
	userList.push(user);
    });
    return userList;
}

function extractEmailSettingsFromInputData(data) {
    if(data.buttonList === undefined) {
	servicelog("inputData does not contain buttonList");
	return null;
    }
    return { enabled: data.items[1].frame[0][1][0].checked,
	     host: data.items[1].frame[1][1][0].value,
	     user: data.items[1].frame[2][1][0].value,
	     sender: data.items[1].frame[3][1][0].value,
	     password: data.items[1].frame[4][1][0].value,
	     ssl: data.items[1].frame[5][1][0].checked,
	     blindlyTrust: data.items[1].frame[6][1][0].checked };
}

function extractPasswordChangeFromInputData(data) {
    if(data.buttonData === undefined) {
	servicelog("inputData does not contain buttonData");
	return null;
    }
    if(data.items === undefined) {
	servicelog("inputData does not contain items");
	return null;
    }
    if(data.items[0] === undefined) {
	servicelog("inputData.items is not an array");
	return null;
    }
    if(data.items[0].frame === undefined) {
	servicelog("inputData.items does not contain frame");
	return null;
    }
    var passwordChange = data.items[0].frame.map(function(u) {
	if(u[0][0].text === data.buttonData) {
	    return { userName: u[0][0].text,
		     password: getPasswordHash(u[0][0].text, u[6][1].value) };
	}
    }).filter(function(f){return f;})[0];
    return passwordChange;
}



function processUserAccountRequest(data) {
    var session = refreshSessionByToken(data.token, data.data);
    if(!session) {
	servicelog("Incoming message verification failed");
	return {result: restStatusMessage("E_VERIFYSESSION")};
    }
    var account = createLoggedinUserAccountChange(session);
    return sendUserAccountModificationDialog(account, session.key, true);
}

// User handling functions

function changeUserAccount(account) {
    var request = commitPendingRequest(account.checksum);
    if(!request.isNewAccount) {
	account.username = request.username;
    }
    var newUsers = [];
    var oldUsers = runCallbackByName("datastorageRead", "users").users;
    var flag = true;
    oldUsers.forEach(function(u) {
	if(u.username === account.username) {
	    flag = false;
	    var newPassword = "";
	    if(account.password === "") {
		newPassword = u.password;
	    } else {
		newPassword = getPasswordHash(account.username, account.password);
	    }
	    newUsers.push({ username: account.username,
			    hash: sha1.hash(account.username),
			    password: newPassword,
			    email: account.email,
			    realname: account.realname,
			    phone: account.phone,
			    language: account.language,
			    applicationData: u.applicationData });
	} else {
	    newUsers.push(u);
	}
    });
    if(flag) {
	newUsers.push({ username: account.username,
			hash: sha1.hash(account.username),
			password: getPasswordHash(account.username, account.password),
			email: account.email,
			realname: account.realname,
			phone: account.phone,
			language: account.language,
			applicationData: { priviliges: runCallbackByName("createDefaultPriviliges") } });
    }
    if(runCallbackByName("datastorageWrite", "users", { users: newUsers }) === false) {
	servicelog("User database write failed");
    } else {
	servicelog("Updated User database.");
    }
}

function getPasswordHash(username, password) {
    return sha1.hash(password + sha1.hash(username).slice(0,4));
}

function getUserByHashedUserName(hash) {
    return runCallbackByName("datastorageRead", "users").users.filter(function(u) {
	return u.hash === hash;
    })[0];
}

function getUserByEmail(email) {
    var user = runCallbackByName("datastorageRead", "users").users.filter(function(u) {
	return u.email === email;
    });
    if(user.length === 0) {
	return null;
    } else {
	return user[0];
    }
}

function getUserNameByEmail(email) {
    var user = getUserByEmail(email);
    if(user !== null) {
	return user.username;
    } else {
	return "";
    }
}

function getUserByUsername(username) {
    var user = runCallbackByName("datastorageRead", "users").users.filter(function(u) {
	return u.username === username;
    });
    if(user.length === 0) {
	return false;
    } else {
	return user[0];
    }
}

function getUserPriviliges(user) {
    if(user.applicationData.priviliges.length === 0) { return []; }
    if(user.applicationData.priviliges.indexOf("none") > -1) { return []; }
    return user.applicationData.priviliges;
}

function userHasPrivilige(privilige, user) {
    if(user.applicationData.priviliges.length === 0) { return false; }
    if(user.applicationData.priviliges.indexOf(privilige) < 0) { return false; }
    return true;
}

function getNewSessionKey() {
    if(typeof this.counter == 'undefined' ) {
	this.counter = 0;
    }
    this.counter++;
    return (sha1.hash(globalSalt + new Date().getTime().toString() + this.counter));
}


// email handling functions

function sendVerificationEmail(recipientAddress) {
    var request = createPendingRequest(recipientAddress, false);
    if(!request) {
	servicelog("Failed to create pending request");
	return { result: restStatusMessage("E_INTERNALERROR"),
		 message: "Internal Error" };
    }
    if(request.isNewAccount) {
	var emailSubject = ui.getLanguageText(null, "EMAILSUBJECT_NEWACCOUNTREQUEST");
	var emailBody = ui.fillTagsInText(ui.getLanguageText(null, "EMAILBODY_NEWACCOUNTREQUEST"),
					  applicationName,
					  request.token.mail + request.token.key);
    } else {
	var emailSubject = ui.getLanguageText(null, "EMAILSUBJECT_NEWPASSWORDREQUEST");
	var emailBody = ui.fillTagsInText(ui.getLanguageText(null, "EMAILBODY_NEWPASSWORDREQUEST"),
					  request.username,
					  applicationName,
					  request.token.mail + request.token.key);
    }
    var mailDetails = { text: emailBody,
			from: runCallbackByName("datastorageRead", "email").sender,
			to: recipientAddress,
			subject: emailSubject };
    sendEmail(mailDetails, "account verification");
}

function sendEmail(emailDetails, logLine) {
    var emailData = runCallbackByName("datastorageRead", "email");
    if(emailData.blindlyTrust) {
	servicelog("Trusting self-signed certificates");
	process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    }
    email.server.connect({
	user: emailData.user,
	password: emailData.password,
	host: emailData.host,
	ssl: emailData.ssl
    }).send(emailDetails, function(err, message) {
	if(err) {
	    servicelog(err + " : " + JSON.stringify(message));
	} else {
	    servicelog("Sent " + logline + " email to " + emailDetails.to);
	}
    });
}

function sendConfirmationEmails(account) {
    if(account.isNewAccount) {
	var emailSubject = ui.getLanguageText(null, "EMAILSUBJECT_NEWACCOUNTCONFIRM");
	var emailBody = ui.fillTagsInText(ui.getLanguageText(null, "EMAILBODY_NEWACCOUNTCONFIRM"),
				       account.username,
				       applicationName,
				       runCallbackByName("datastorageRead", "main").main.siteFullUrl);
	var adminEmailSubject = ui.getLanguageText(null, "EMAILSUBJECT_NEWACCOUNTCREATED");
	var adminEmailBody = ui.fillTagsInText(ui.getLanguageText(null, "EMAILBODY_NEWACCOUNTCREATED"),
					    account.username,
					    applicationName);
    } else {
	var emailSubject = ui.getLanguageText(null, "EMAILSUBJECT_NEWPASSWORDCONFIRM");
	var emailBody = ui.fillTagsInText(ui.getLanguageText(null, "EMAILBODY_NEWPASSWORDCONFIRM"),
				       account.username,
				       applicationName,
				       runCallbackByName("datastorageRead", "main").main.siteFullUrl);
	var adminEmailSubject = ui.getLanguageText(null, "EMAILSUBJECT_USERHASCHANGEDPASSWORD");
	var adminEmailBody = ui.fillTagsInText(ui.getLanguageText(null, "EMAILBODY_USERHASCHANGEDPASSWORD"),
					    account.username,
					    applicationName);
    }
    var mailDetails = { text: emailBody,
			from: runCallbackByName("datastorageRead", "email").sender,
			to: account.email,
			subject: emailSubject };
    sendEmail(mailDetails, "account confirmation");
    runCallbackByName("datastorageRead", "users").users.map(function(u) {
	if(userHasPrivilige("system-admin", u)) { return u.email; }
    }).filter(function(f){return f;}).forEach(function(m) {
	var mailDetails = { text: adminEmailBody,
			    from: runCallbackByName("datastorageRead", "email").sender,
			    to: m,
			    subject: adminEmailSubject };
	sendEmail(mailDetails, "admin confirmation");
    });
}


// Pending list handling

function createPendingRequest(emailAddress, loggedIn) {
    removePendingRequest(emailAddress);
    var pendingData = runCallbackByName("datastorageRead", "pending");
    var timeout = new Date();
    var emailToken =  { mail: sha1.hash(emailAddress).slice(0, 8),
			key: sha1.hash(globalSalt + JSON.stringify(new Date().getTime())).slice(0, 16) };
    var username = getUserNameByEmail(emailAddress);
    var isNewAccount = false;
    if(username === "") { isNewAccount = true; }
    timeout.setHours(timeout.getHours() + 24);
    var request = { email: emailAddress,
		    isNewAccount: isNewAccount,
		    username: username,
                    token: emailToken,
                    date: timeout.getTime(),
		    loggedIn: loggedIn,
		    state: "pending" };
    var checksum = sha1.hash(JSON.stringify(request));
    request.checksum = checksum;
    pendingData.pending.push(request);
    if(runCallbackByName("datastorageWrite", "pending", pendingData) === false) {
	servicelog("Pending database write failed");
	return false;
    } else {
	servicelog("Created pending request");
	return request;
    }
}

function removePendingRequest(emailAdress) {
    var pendingUserData = runCallbackByName("datastorageRead", "pending");
    if(Object.keys(pendingUserData.pending).length === 0) {
	servicelog("Empty pending requests database, bailing out");
	return;
    }
    if(pendingUserData.pending.filter(function(u) {
	return u.email === emailAdress;
    }).length !== 0) {
	servicelog("Removing existing entry from pending database");
	var newPendingUserData = { pending: [] };
	newPendingUserData.pending = pendingUserData.pending.filter(function(u) {
            return u.email !== emailAdress;
	});
	if(runCallbackByName("datastorageWrite", "pending", newPendingUserData) === false) {
            servicelog("Pending requests database write failed");
	}
    } else {
	servicelog("no existing entries in pending database");
    }
}

function validatePendingRequest(emailHash) {
    var pendingUserData = runCallbackByName("datastorageRead", "pending").pending;
    if(Object.keys(pendingUserData).length === 0) {
	servicelog("Empty pending requests database, bailing out");
	return false;
    }
    var target = pendingUserData.filter(function(u) {
	return u.token.mail === emailHash.slice(0, 8);
    });
    if(target.length === 0) {
	servicelog("Cannot find a pending request");
	return false;
    }
    if(target[0].state != "pending") {
	servicelog("Cannot validate a pending request in wrong state");
	return false;
    }
    target[0].state = "validated";
    var newPendingUserData = pendingUserData.filter(function(u) {
	return u.token.mail !== emailHash.slice(0, 8);
    });
    newPendingUserData.push(target[0]);
    if(runCallbackByName("datastorageWrite", "pending", { pending: newPendingUserData }) === false) {
	servicelog("Pending requests database write failed");
    }
    servicelog("Validated pending request");
    return target[0];
}

function getValidatedPendingRequest(checksum) {
    var pendingUserData = runCallbackByName("datastorageRead", "pending").pending;
    if(Object.keys(pendingUserData).length === 0) {
	servicelog("Empty pending requests database, bailing out");
	return false;
    } 
    var target = pendingUserData.filter(function(u) {
	return u.checksum === checksum;
    });
    if(target.length === 0) {
	servicelog("Cannot find a pending request");
	return false;
    }
    if(target[0].state !== "validated") {
	servicelog("Cannot get a pending request in wrong state");
	return false;
    }
    return target[0];
}

function commitPendingRequest(checksum) {
    var pendingUserData = runCallbackByName("datastorageRead", "pending").pending;
    if(Object.keys(pendingUserData).length === 0) {
	servicelog("Empty pending requests database, bailing out");
	return false;
    } 
    var target = pendingUserData.filter(function(u) {
	return u.checksum === checksum;
    });
    if(target.length === 0) {
	servicelog("Cannot find a pending request");
	return false;
    }
    var newPendingUserData = [];
    newPendingUserData = pendingUserData.filter(function(u) {
	return u.checksum !== checksum;
    });
    if(runCallbackByName("datastorageWrite", "pending", { pending: newPendingUserData }) === false) {
	servicelog("Pending requests database write failed");
    }
    return target[0];
}

setInterval(function() {
    var now = new Date().getTime();
    var pendingData = runCallbackByName("datastorageRead", "pending");
    if(Object.keys(pendingData.pending).length === 0) {
	servicelog("No pending requests to purge");
	return;
    }
    var purgeCount = 0
    var newPendingData = { pending: [] };
    pendingData.pending.forEach(function(p) {
	if(p.date < now) {
	    purgeCount++;
	} else {
	    newPendingData.pending.push(p);
	}
    });
    if(purgeCount === 0) {
	servicelog("No pending requests timeouted");
	return;
    } else {
	if(runCallbackByName("datastorageWrite", "pending", newPendingData) === false) {
	    servicelog("Pending requests database write failed");
	} else {
	    servicelog("Removed " + purgeCount + " timeouted pending requests");
	}
    }
}, 1000*60*60);


// session list handling

function createSession(key, username, token, serial) {
    var sessionData = runCallbackByName("datastorageRead", "session");
    var timeout = new Date();
    timeout.setMinutes(timeout.getMinutes() + 10);
    var request = { key: key,
		    token: token,
		    date: timeout,
		    serial: serial,
		    username: username }
    sessionData.session.push(request);
    if(runCallbackByName("datastorageWrite", "session", sessionData) === false) {
	servicelog("Session database write failed");
	return false;
    } else {
	servicelog("Created new session");
	return true;
    }
}

function getSessionByToken(token) {
    var session = runCallbackByName("datastorageRead", "session").session.filter(function(s) {
	return s.token === token;
    });
    if(session.length === 0) {
	return false;
    } else {
	return session[0];
    }
}

function refreshSessionByToken(token, data) {
    var session = getSessionByToken(token);
    if(!session) { return false }
    var user = getUserByUsername(session.username);
    if(!user) { return false }
    var serialToken = JSON.parse(Aes.Ctr.decrypt(data, session.key, 128));
    if(serialToken.token !== token) { return false }
    var serial = parseInt(session.serial) + 1;
    if(parseInt(serialToken.serial) !== serial) { return false }
    var newSessionData = [];
    var session;
    var timeout = new Date();
    timeout.setMinutes(timeout.getMinutes() + 10);
    runCallbackByName("datastorageRead", "session").session.forEach(function(s) {
	if(s.token === token) {
	    s.date = timeout;
	    s.serial = serial;
	    session = s;
	}
	newSessionData.push(s);
    });
    if(runCallbackByName("datastorageWrite", "session", {session: newSessionData}) === false) {
	servicelog("Session database write failed");
	return false;
    } else {
//	servicelog("Updated session");
	return session;
    }
}

function deleteSessionByToken(token, data) {
    var session = getSessionByToken(token);
    if(!session) { return false }
    var user = getUserByUsername(session.username);
    if(!user) { return false }
    var serialToken = JSON.parse(Aes.Ctr.decrypt(data, session.key, 128));
    if(serialToken.token !== token) { return false }
    var newSessionData = [];
    runCallbackByName("datastorageRead", "session").session.forEach(function(s) {
	if(s.token !== token) { newSessionData.push(s); }
    });
    if(runCallbackByName("datastorageWrite", "session", {session: newSessionData}) === false) {
	servicelog("Session database write failed");
	return false;
    } else {
	servicelog("Deleted session");
	return true;
    }
}

setInterval(function() {
    var now = new Date().getTime();
    var sessionData = runCallbackByName("datastorageRead", "session");
    if(Object.keys(sessionData.session).length === 0) {
	servicelog("No sessions to purge");
	return;
    }
    var purgeCount = 0
    var newSessionData = { session: [] };
    sessionData.session.forEach(function(s) {
	if(s.date < now) {
	    purgeCount++;
	} else {
	    newSessionData.session.push(s);
	}
    });
    if(purgeCount === 0) {
	servicelog("No sessions timeouted");
	return;
    } else {
	if(runCallbackByName("datastorageWrite", "session", newSessionData) === false) {
	    servicelog("Session database write failed");
	} else {
	    servicelog("Removed " + purgeCount + " timeouted sessions");
	}
    }
}, 1000*60);


// Initialize internal datastorages

function initializeDataStorages() {
    runCallbackByName("datastorageInitialize", "main", { main: { version: 1,
								port: 8080,
								siteFullUrl: "http://url.to.my.site/",
								emailVerification: false,
								defaultLanguage: "english" } });
    runCallbackByName("datastorageInitialize", "users", { users: [ { username: "test",
								    hash: sha1.hash("test"),
								    password: getPasswordHash("test", "test"),
								    applicationData: { priviliges: ["system-admin"] },
								    realname: "",
								    email: "",
								    phone: "",
								    language: runCallbackByName("datastorageRead",
											       "main").main.defaultLanguage } ] }, true);
    runCallbackByName("datastorageInitialize", "session", { session: [] });
    runCallbackByName("datastorageInitialize", "pending", { pending: [] }, true);
    runCallbackByName("datastorageInitialize", "email", { host: "smtp.your-email.com",
							 user: "username",
							 password: "password",
							 sender: "you <username@your-email.com>",
							 ssl: true,
							 blindlyTrust: true });
    runCallbackByName("datastorageInitialize", "language", { languages: [], dictionary: [] });

    // sessions are cleared between restarts
    runCallbackByName("datastorageWrite", "session", { session: [] });
}


// Callback to the application specific part handling

var functionList = [];

function setCallback(name, callback) {
    functionList.push({ name: name, function: callback });
}

function runCallbackByName(name, par1, par2, par3, par4, par5) {
    for (var i = 0; i < functionList.length; i++) {
	if(functionList[i]["name"] === name) {
	    return functionList[i].function(par1, par2, par3, par4, par5);
	}
    }
    servicelog("ERROR: Function \"" + name + "\" has not been pushed as a callback!");
    servicelog("Exiting program.");
    process.exit(1);
}

function startUiLoop() {
    initializeDataStorages();
    if(runCallbackByName("datastorageRead", "language").languages.length === 0) {
	servicelog("ERROR: Missing language definition file!");
	servicelog("Copy the 'language.json' file from framework to './configuration/' directory!");
	servicelog("Exiting program.");
	process.exit(1);
    }
    listenPort = runCallbackByName("datastorageRead", "main").main.port;
    webServer.listen(listenPort, function() {
	servicelog("Waiting for client connection to port " + listenPort + "...");
    });
}

module.exports.servicelog = servicelog;
module.exports.setApplicationName = setApplicationName;
module.exports.encrypt = encrypt;
module.exports.decrypt = decrypt;
module.exports.restStatusMessage = restStatusMessage;
module.exports.startUiLoop = startUiLoop;
module.exports.initializeDataStorages = initializeDataStorages;
module.exports.setCallback = setCallback;
module.exports.runCallbackByName = runCallbackByName;
module.exports.getUserByUsername = getUserByUsername;
module.exports.userHasPrivilige = userHasPrivilige;
module.exports.refreshSessionByToken = refreshSessionByToken;
/*
module.exports.createUiTextNode = createUiTextNode;
module.exports.createUiTextArea = createUiTextArea;
module.exports.createUiCheckBox = createUiCheckBox;
module.exports.createUiSelectionList = createUiSelectionList;
module.exports.createUiMessageButton = createUiMessageButton;
module.exports.createUiFunctionButton = createUiFunctionButton;
module.exports.createUiInputField = createUiInputField;
module.exports.createUiHtmlCell = createUiHtmlCell;
module.exports.createTopButtons = createTopButtons;
module.exports.sendCipherTextToClient = sendCipherTextToClient;
module.exports.setStatustoClient = setStatustoClient;
module.exports.userHasPrivilige = userHasPrivilige;
module.exports.getConnectionList = getConnectionList;
*/
