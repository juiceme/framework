var websocket = require("websocket");
var http = require("http");
var fs = require("fs");
var email = require("emailjs/email");
var Aes = require('./crypto/aes.js');
Aes.Ctr = require('./crypto/aes-ctr.js');
var sha1 = require('./crypto/sha1.js');

var websocPort = 0;
var globalSalt = sha1.hash(JSON.stringify(new Date().getTime()));
var fragmentSize = 10000;
var applicationName = "<name not set>";

function servicelog(s) {
    console.log((new Date()) + " --- " + s);
}

function setStatustoClient(cookie, status) {
    if(cookie.aesKey === "") {
	sendPlainTextToClient(cookie, { type: "statusData", content: status });
    } else {
	sendCipherTextToClient(cookie, { type: "statusData", content: status });
    }
}

function sendPlainTextToClient(cookie, sendable) {
    cookie.connection.send(JSON.stringify(sendable));
}

function sendFragment(cookie, type, id, data) {
    var fragment = JSON.stringify({ type: type, id: id, length: data.length, data: data });
    var cipherSendable = JSON.stringify({ type: "payload",
					  content: Aes.Ctr.encrypt(fragment, cookie.aesKey, 128) });
    cookie.connection.send(cipherSendable);
}

function sendCipherTextToClient(cookie, sendable) {
    var sendableString = JSON.stringify(sendable);
    var count = 0;
    var originalLength = sendableString.length;
    if(sendableString.length <= fragmentSize) {
	sendFragment(cookie, "nonFragmented", count++, sendableString);
    } else {
	while(sendableString.length > fragmentSize) {
	    sendableStringFragment = sendableString.slice(0, fragmentSize);
	    sendableString = sendableString.slice(fragmentSize, sendableString.length);
	    sendFragment(cookie, "fragment", count++, sendableStringFragment);
	}
	if(sendableString.length > 0) {
	    sendFragment(cookie, "lastFragment", count++, sendableString);
	}
    }
//    servicelog("Sent " + originalLength + " bytes in " + count + " fragments to server");
}

function getClientVariables() {
    return "var WEBSOCK_PORT = " + websocPort + ";\n";
}

var webServer = http.createServer(function(request,response){
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
});

wsServer = new websocket.server({
    httpServer: webServer,
    autoAcceptConnections: false
});

var connectionCount = 0;

wsServer.on('request', function(request) {
    servicelog("Connection from origin " + request.origin);
    var connection = request.accept(null, request.origin);
    var cookie = { count:connectionCount++, connection:connection, state:"new" };
    var sendable;
    var defaultUserRights = { priviliges: [ "none" ] }
    servicelog("Client #" + cookie.count  + " accepted");

    connection.on('message', function(message) {
        if (message.type === 'utf8') {
	    try {
		var receivable = JSON.parse(message.utf8Data);
	    } catch(err) {
		servicelog("Received illegal message: " + err);
		return;
	    }
	    if(!receivable.type || !receivable.content) {
		servicelog("Received broken message: " + JSON.stringify(receivable));
		return;
	    }

//	    servicelog("Incoming message: " + JSON.stringify(receivable));
	    var type = receivable.type;
	    var content = receivable.content;

            if(type === "clientStarted") { processClientStarted(cookie); }
	    if(type === "userLogin") { processUserLogin(cookie, content); }
	    if(type === "createOrModifyAccount") { processCreateOrModifyAccount(cookie, content); }
	    if(type === "accountRequestMessage") { processAccountRequestMessage(cookie, content); }
	    if(type === "validateAccountMessage") { processValidateAccountMessage(cookie, content); }
	    if(type === "loginResponse") { processLoginResponse(cookie, content); }
	    if(type === "payload") {
		try {
		    var decryptedMessage = JSON.parse(Aes.Ctr.decrypt(content, cookie.aesKey, 128));
		    defragmentIncomingMessage(cookie, decryptedMessage);
		} catch(err) {
		    servicelog("Problem parsing JSON from message: " + err);
		    return;
		}
	    }
	}
    });

    connection.on('close', function(connection) {
	servicelog("Client #" + cookie.count  + " disconnected");
        cookie = {};
    });
});

function defragmentIncomingMessage(cookie, decryptedMessage) {
    if(decryptedMessage.type === "nonFragmented") {
	handleIncomingMessage(cookie, JSON.parse(decryptedMessage.data));
    }
    if(decryptedMessage.type === "fragment") {
	if(decryptedMessage.id === 0) {
	    cookie.incomingMessageBuffer = decryptedMessage.data;
	} else {
	    cookie.incomingMessageBuffer = cookie.incomingMessageBuffer + decryptedMessage.data;
	}
    }
    if(decryptedMessage.type === "lastFragment") {
	cookie.incomingMessageBuffer = cookie.incomingMessageBuffer + decryptedMessage.data;
	handleIncomingMessage(cookie, JSON.parse(cookie.incomingMessageBuffer));
    }
}

function handleIncomingMessage(cookie, decryptedMessage) {
//    servicelog("Decrypted message: " + JSON.stringify(decryptedMessage));
    if(decryptedMessage.type === "clientStarted") {
	processClientStarted(cookie); }
    if(decryptedMessage.type === "userAccountChangeMessage") {
	processUserAccountChangeMessage(cookie, decryptedMessage.content); }
    if(stateIs(cookie, "loggedIn")) {
	if(decryptedMessage.type === "gainAdminMode") {
	    processGainAdminMode(cookie, decryptedMessage.content); }
	if(decryptedMessage.type === "saveAdminData") {
	    processSaveAdminData(cookie, decryptedMessage.content); }
	if(decryptedMessage.type === "changeUserPassword") {
	    processChangeUserPassword(cookie, decryptedMessage.content); }
	// if nothing here matches, jump to application message handler
	runCallbacByName("handleApplicationMessage", cookie, decryptedMessage);
    }
}

function stateIs(cookie, state) {
    return (cookie.state === state);
}

function setState(cookie, state) {
    cookie.state = state;
}

function getUserByHashedUserName(hash) {
    return runCallbacByName("datastorageRead", "users").users.filter(function(u) {
	return u.hash === hash;
    });
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

function getPasswordHash(username, password) {
    return sha1.hash(password + sha1.hash(username).slice(0,4));
}

function getNewChallenge() {
    return ("challenge_" + sha1.hash(globalSalt + new Date().getTime().toString()) + "1");
}

function processClientStarted(cookie) {
    if(cookie["user"] !== undefined) {
	if(cookie.user["username"] !== undefined) {
	    servicelog("User " + cookie.user.username + " logged out");
	}
    }
    servicelog("Sending initial login view to client #" + cookie.count);
    setState(cookie, "clientStarted");
    cookie.aesKey = "";
    cookie.user = {};
    cookie.challenge = "";
    cookie.incomingMessageBuffer = "";
    var items = [];
    items.push([ [ createUiTextNode("username", getLanguageText(null, "TERM_USERNAME") + ":") ],
		 [ createUiInputField("userNameInput", "", false) ] ]);
    items.push([ [ createUiTextNode("password", getLanguageText(null, "TERM_PASSWORD") + ":") ],
		 [ createUiInputField("passwordInput", "", true) ] ]);
    var itemList = { title: getLanguageText(null, "PROMPT_LOGIN"),
                     frameId: 0,
                     header: [ { text: "" }, { text: "" } ],
		     rowNumbers: false,
                     items: items };
    var frameList = [ { frameType: "fixedListFrame", frame: itemList } ];
    var buttonList = [ { id: 501,
			 text: getLanguageText(null, "BUTTON_LOGIN"),
			 callbackFunction: "var username=''; var password=''; document.querySelectorAll('input').forEach(function(i){ if(i.key === 'userNameInput') { username = i.value; }; if(i.key === 'passwordInput') { password = i.value; }; }); sessionPassword=Sha1.hash(password + Sha1.hash(username).slice(0,4)); sendToServer('userLogin', { username: Sha1.hash(username) } ); return false;" } ];
    if(runCallbacByName("datastorageRead", "main").main.emailVerification) {
	buttonList.push({ id: 502,
			  text: getLanguageText(null, "BUTTON_NEWACCOUNT"),
			  callbackFunction: "sessionPassword=''; sendToServer('createOrModifyAccount', {}); return false;" });
    }
    var sendable = { type: "createUiPage",
                     content: { frameList: frameList,
				buttonList: buttonList } };
    sendPlainTextToClient(cookie, sendable);
    setStatustoClient(cookie, "Login");
}

function processUserLogin(cookie, content) {
    var sendable;
    if(!content.username) {
	servicelog("Illegal user login message");
	processClientStarted(cookie);
	return;
    } else {
	var user = getUserByHashedUserName(content.username);
	if(user.length === 0) {
	    servicelog("Unknown user login attempt");
	    processClientStarted(cookie);
	    return;
	} else {
	    cookie.user = user[0];
	    cookie.aesKey = user[0].password;
	    servicelog("User " + user[0].username + " logging in");
	    var plainChallenge = getNewChallenge();
	    servicelog("plainChallenge: " + plainChallenge);
	    cookie.challenge = plainChallenge;
	    sendable = { type: "loginChallenge",
			 content: plainChallenge };
	    sendCipherTextToClient(cookie, sendable);
	}
    }
}

function processLoginResponse(cookie, content) {
    var sendable;
    var plainResponse = Aes.Ctr.decrypt(content, cookie.aesKey, 128);
    if(cookie.challenge === plainResponse) {
	servicelog("User login OK");
	setState(cookie, "loggedIn");
	setStatustoClient(cookie, "Login OK");
	if(getUserPriviliges(cookie.user).length === 0) {
	    // for unpriviliged login, only send logout button and nothing more
	    sendable = { type: "unpriviligedLogin",
			 content: { topButtonList: [ { id: 100,
						       text: "Log Out",
						       callbackMessage: "clientStarted" } ] } };

	    sendCipherTextToClient(cookie, sendable);
	    servicelog("Sent unpriviligedLogin info to client #" + cookie.count);
	} else {
	    // Login succeeds, start the UI engine
	    runCallbacByName("processResetToMainState", cookie);
	}
    } else {
	servicelog("User login failed on client #" + cookie.count);
	processClientStarted(cookie);
    }
}

function processCreateOrModifyAccount(cookie) {
    var items = [];
    items.push([ [ createUiTextNode("email", getLanguageText(null, "TERM_EMAIL") + ":" ) ],
		 [ createUiInputField("emailInput", "", false) ],
		 [ createUiFunctionButton(getLanguageText(null, "BUTTON_SENDEMAIL"), "var email=''; document.querySelectorAll('input').forEach(function(i){ if(i.key === 'emailInput') { email = i.value; }; }); sendToServer('accountRequestMessage', {email:email}); return false;") ] ]);
    items.push([ [ createUiTextNode("verification", getLanguageText(null, "TERM_VERIFICATIONCODE") + ":" ) ],
		 [ createUiInputField("verificationInput", "", false) ],
		 [ createUiFunctionButton(getLanguageText(null, "BUTTON_VALIDATEACCOUNT"), "var code=''; document.querySelectorAll('input').forEach(function(i){ if(i.key === 'verificationInput') { code = i.value; }; }); sessionPassword = code.slice(8,24); sendToServer('validateAccountMessage', { email: code.slice(0,8), challenge: Aes.Ctr.encrypt('clientValidating', sessionPassword, 128) });") ] ]);
    var itemList = { title: getLanguageText(null, "PROMPT_CHANGEACCOUNT"),
                     frameId: 0,
                     header: [ { text: "" }, { text: "" }, { text: "" } ],
		     rowNumbers: false,
                     items: items };
    var frameList = [ { frameType: "fixedListFrame", frame: itemList } ];
    var sendable = { type: "createUiPage",
                     content: { frameList: frameList,
				buttonList: [ { id: 501,
						text: getLanguageText(null, "BUTTON_CANCEL"),
						callbackFunction: "sessionPassword=''; sendToServer('clientStarted', {}); return false;" } ] } };
    sendPlainTextToClient(cookie, sendable);
    setStatustoClient(cookie, "Modify account");
}

function processAccountRequestMessage(cookie, content) {
    servicelog("Request for email verification: [" + content.email + "]");
    sendVerificationEmail(cookie, content.email);
    processClientStarted(cookie);
    setStatustoClient(cookie, "Email sent!");
}

function processValidateAccountMessage(cookie, content) {
    if(!content.email || !content.challenge) {
	servicelog("Illegal validate account message");
	processClientStarted(cookie);
	return;
    } else {
	servicelog("Validation code: " + JSON.stringify(content));
	var account = validatePendingRequest(content.email.toString());
	if(account === false) {
	    servicelog("Failed to validate pending request");
	    processClientStarted(cookie);
	    return;
	}
	if(Aes.Ctr.decrypt(content.challenge, account.token.key, 128) !== "clientValidating") {
	    servicelog("Failed to validate code");
	    processClientStarted(cookie);
	    return;
	}
	setState(cookie, "newUserValidated");
	cookie.aesKey = account.token.key;
	var newAccount = { checksum: account.checksum,
			   isNewAccount: true,
			   email: account.email,
			   username: "",
			   realname: "",
			   phone: "",
			   language: runCallbacByName("datastorageRead", "main").main.defaultLanguage };
	cookie.user.language = newAccount.language;
	var user = getUserByEmail(account.email);
	if(user !== null) {
	    newAccount.isNewAccount = false;
	    newAccount.username = user.username;
	    newAccount.realname = user.realname;
	    newAccount.phone = user.phone;
	    newAccount.language = user.language;
	    setState(cookie, "oldUserValidated");
	    cookie.user.language = user.language;
	}
	sendUserAccountModificationDialog(cookie, newAccount);
	return;
    }
}

function validatePendingRequest(emailHash) {
    var pendingUserData = runCallbacByName("datastorageRead", "pending").pending;
    if(Object.keys(pendingUserData).length === 0) {
	servicelog("Empty pending requests database, bailing out");
	return false;
    } 
    var target = pendingUserData.filter(function(u) {
	return u.token.mail === emailHash.slice(0, 8);
    });
    if(target.length === 0) {
	return false;
    }
    if(target[0].state != "pending") {
	return false;
    }
    target[0].state = "verified";
    var user = getUserByEmail(target[0].email);
    if(user !== null) {
	target[0].username = user.username;
    } else {
	target[0].username = "";
    }
    var newPendingUserData = [];
    newPendingUserData = pendingUserData.filter(function(u) {
	return u.token.mail !== emailHash.slice(0, 8);
    });
    newPendingUserData.push(target[0]);
    if(runCallbacByName("datastorageWrite", "pending", { pending: newPendingUserData }) === false) {
	servicelog("Pending requests database write failed");
    }
    return target[0];
}

function commitPendingRequest(checksum) {
    var pendingUserData = runCallbacByName("datastorageRead", "pending").pending;
    if(Object.keys(pendingUserData).length === 0) {
	servicelog("Empty pending requests database, bailing out");
	return false;
    } 
    var target = pendingUserData.filter(function(u) {
	return u.checksum === checksum;
    });
    if(target.length === 0) {
	return false;
    }
    var newPendingUserData = [];
    newPendingUserData = pendingUserData.filter(function(u) {
	return u.checksum !== checksum;
    });
        if(runCallbacByName("datastorageWrite", "pending", { pending: newPendingUserData }) === false) {
	servicelog("Pending requests database write failed");
    }
    return target[0];
}

function sendUserAccountModificationDialog(cookie, account) {
    var title = "";
    var items = [];
    items.push([ [ createUiTextNode("email", getLanguageText(cookie, "TERM_EMAIL") + ":") ],
		 [ createUiInputField("emailInput", account.email, false) ] ]);
    if(account.isNewAccount) {
	title = getLanguageText(cookie, "PROMPT_CREATENEWACCOUNT");
	items.push([ [ createUiTextNode("username", getLanguageText(cookie, "TERM_USERNAME") + ":") ],
		     [ createUiInputField("usernameInput", account.username, false) ] ]);
    } else {
	title = getLanguageText(cookie, "PROMPT_MODIFYOLDACCOUNT");
	items.push([ [ createUiTextNode("username", getLanguageText(cookie, "TERM_USERNAME") + ":") ],
		     [ createUiInputField("usernameInput", account.username, false, true) ] ]);
    }
    items.push([ [ createUiTextNode("realname", getLanguageText(cookie, "TERM_REALNAME")) ],
		 [ createUiInputField("realnameInput", account.realname, false) ] ]);
    items.push([ [ createUiTextNode("phone", getLanguageText(cookie, "TERM_PHONE")) ],
		 [ createUiInputField("phoneInput", account.phone, false) ] ]);
    items.push([ [ createUiTextNode("language", getLanguageText(cookie, "TERM_LANGUAGE")) ],
		 [ createUiSelectionList("languageInput", runCallbacByName("datastorageRead" ,"language").languages, account.language, true, false) ] ]);
    items.push([ [ createUiTextNode("password1", getLanguageText(cookie, "TERM_PASSWORD")) ],
		 [ createUiInputField("passwordInput1", "", true) ] ]);
    items.push([ [ createUiTextNode("password2", getLanguageText(cookie, "TERM_REPEATPASSWORD")) ],
		 [ createUiInputField("passwordInput2", "", true) ] ]);
    var itemList = { title: title,
                     frameId: 0,
                     header: [ { text: "" }, { text: "" } ],
		     rowNumbers: false,
                     items: items };
    var frameList = [ { frameType: "fixedListFrame", frame: itemList } ];
    var sendable = { type: "createUiPage",
                     content: { frameList: frameList,
				buttonList: [ { id: 501,
						text: getLanguageText(cookie, "BUTTON_CANCEL"),
						callbackFunction: "sessionPassword=''; sendToServer('clientStarted', {}); return false;" },
					      { id: 502,
						text: getLanguageText(cookie, "BUTTON_OK"),
						callbackFunction: "var userData=[{ key:'checksum', value:'" + account.checksum + "' }, { key:'isNewAccount', value:" + account.isNewAccount + " }]; document.querySelectorAll('input').forEach(function(i){ if(i.key != undefined) { userData.push({ key:i.key, value:i.value } ); } }); document.querySelectorAll('select').forEach(function(i){ if(i.key != undefined) { userData.push({ key:i.key, selected:i.options[i.selectedIndex].item } ); } }); sendToServerEncrypted('userAccountChangeMessage', { userData: userData } ); return false;" } ] } };
    sendCipherTextToClient(cookie, sendable);
    setStatustoClient(cookie, "Modify account");
}

function processUserAccountChangeMessage(cookie, content) {
    if(content.userData === undefined) {
	servicelog("User account change contains no data.");
	processClientStarted(cookie);
	return;
    }
    var account = { checksum: findObjectByKey(content.userData, "key", "checksum").value,
		    isNewAccount: findObjectByKey(content.userData, "key", "isNewAccount").value,
		    email: findObjectByKey(content.userData, "key", "emailInput").value,
		    username: findObjectByKey(content.userData, "key", "usernameInput").value,
		    realname: findObjectByKey(content.userData, "key", "realnameInput").value,
		    phone: findObjectByKey(content.userData, "key", "phoneInput").value,
		    language: findObjectByKey(content.userData, "key", "languageInput").selected };
    if(findObjectByKey(content.userData, "key", "passwordInput1").value != findObjectByKey(content.userData, "key", "passwordInput2").value) {
	cookie.user.language = account.language;
	sendUserAccountModificationDialog(cookie, account);
	setStatustoClient(cookie, "Password mismatch!");
	servicelog("Password mismatch in account change dialog");
    } else {
	account.password = findObjectByKey(content.userData, "key", "passwordInput1").value;
	changeUserAccount(cookie, account);
	sendConfirmationEmails(cookie, account);
	processClientStarted(cookie);
	setStatustoClient(cookie, "User account changed!");
    }
}


// UI helper functions

function createUiTextNode(key, text) {
    return { itemType: "textnode", key: key, text: text };
}

function createUiTextArea(key, value, cols, rows) {
    if(cols === undefined) { cols = 10; }
    if(rows === undefined) { rows = 1; }
    return { itemType: "textarea", key: key, value: value, cols: cols, rows: rows };
}

function createUiCheckBox(key, checked, title, active) {
    if(title === undefined) { title = ""; }
    if(active === undefined) { active = true; }
    return { itemType: "checkbox", key: key, checked: checked, title: title, active: active };
}

function createUiSelectionList(key, list, selected, active, zeroOption) {
    var listItems = list.map(function(i) {
	return { text: i, item: i }
    }).filter(function(f) { return f; });
    if(active === undefined) { active = true; }
    if(zeroOption === undefined) { zeroOption = true; }
    return { itemType: "selection", key: key, list: listItems, selected: selected, active: active, zeroOption: zeroOption };
}

function createUiMessageButton(text, callbackMessage, data, active) {
    if(active === undefined) { active = true; }
    return { itemType: "button", text: text, callbackMessage: callbackMessage, data: data, active: active };
}

function createUiFunctionButton(text, callbackFunction, active) {
    if(active === undefined) { active = true; }
    return { itemType: "button", text: text, callbackFunction: callbackFunction, active: active };
}

function createUiInputField(key, value, password, disabled) {
    if(password === undefined) { password = false; }
    if(disabled === undefined) { disabled = false; }
    return { itemType: "input", key: key, value: value, password: password, disabled: disabled };
}

function createUiHtmlCell(key, value, backgroundColor, onClickFunction) {
    if(backgroundColor === undefined) { backgroundColor = "#f0f0f0" }
    if(onClickFunction === undefined) { onClickFunction = "return;" }
    return { itemType: "htmlcell", key: key, value: value, backgroundColor: backgroundColor, onClickFunction: onClickFunction };
}

function createTopButtons(cookie, adminRequest) {
    if(adminRequest === undefined) { adminRequest = false; }
    var id = 101;
    var topButtonList = [ { id: id++, text: "Log Out", callbackFunction: "sessionPassword=''; sendToServer('clientStarted', {}); return false;" } ];
    runCallbacByName("createTopButtonList", cookie).forEach(function(b) {
	var flag = false; 
	b.priviliges.forEach(function(p) {
	    if(userHasPrivilige(p, cookie.user)) { flag = true; }
	});
	if(flag) {
	    b.button.id = id++;
	    topButtonList.push(b.button);
	}
    });
    if(userHasPrivilige("system-admin", cookie.user)) {
	if(adminRequest) {
	    topButtonList.push( { id: id++, text: "User Mode", callbackMessage: "resetToMain" } );
	} else {
	    topButtonList.push( { id: id++, text: "Admin Mode", callbackMessage: "gainAdminMode" } );
	}
    }
    return topButtonList;
}

// generic helper functions

function findObjectByKey(array, key, value) {
    for (var i = 0; i < array.length; i++) {
        if (array[i][key] === value) {
            return array[i];
        }
    }
    return null;
}

function changeUserAccount(cookie, account) {
    var target = commitPendingRequest(account.checksum);
    if(target.username !== "") {
	account.username = target.username;
    }
    var newUsers = [];
    var oldUsers = runCallbacByName("datastorageRead", "users").users;
    var flag = true;
    oldUsers.forEach(function(u) {
	if(u.username === account.username) {
	    flag = false;
	    newUsers.push({ username: account.username,
			    hash: sha1.hash(account.username),
			    password: getPasswordHash(account.username, account.password),
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
			applicationData: { priviliges: [] } });
    }
    if(runCallbacByName("datastorageWrite", "users", { users: newUsers }) === false) {
	servicelog("User database write failed");
    } else {
	servicelog("Updated User database.");
    }
}


// Adminstration UI panel

function createPriviligeList() {
    var priviligeList = runCallbacByName("createAdminPanelUserPriviliges");
    priviligeList.push({ privilige: "system-admin", code: "a"});
    return priviligeList;
}

function processGainAdminMode(cookie, content) {
    servicelog("Client #" + cookie.count + " requests Sytem Administration priviliges");
    if(userHasPrivilige("system-admin", cookie.user)) {
	servicelog("Granting Sytem Administration priviliges to user " + cookie.user.username);
	var topButtonList =  createTopButtons(cookie, true);
	var items = [];
	var priviligeList = createPriviligeList();
	runCallbacByName("datastorageRead", "users").users.forEach(function(u) {
	    var userPriviliges = [];
	    priviligeList.forEach(function(p) {
		userPriviliges.push(createUiCheckBox(p.privilige, userHasPrivilige(p.privilige, u), p.code));
	    });
	    items.push([ [ createUiTextNode("username", u.username) ],
			 [ createUiTextArea("realname", u.realname, 22) ],
			 [ createUiTextArea("email", u.email, 25) ],
			 [ createUiTextArea("phone", u.phone, 12) ],
			 [ createUiSelectionList("language", runCallbacByName("datastorageRead" ,"language").languages, u.language, true, false) ],
			 userPriviliges,
		         [ createUiMessageButton("Change", "changeUserPassword", u.username),
			   createUiInputField("password", "", true) ] ] )
	});
	var emptyPriviligeList = [];
	priviligeList.forEach(function(p) {
	    emptyPriviligeList.push(createUiCheckBox(p.privilige, false, p.code));
	});
        var priviligeCodes = "";
        createPriviligeList().forEach(function(p) {
            priviligeCodes = priviligeCodes + p.code + " / ";
        });
        priviligeCodes = priviligeCodes.slice(0, priviligeCodes.length-3);
	var userListPanel = { title: getLanguageText(cookie, "PROMPT_USERADMIN"),
			      frameId: 0,
			      header: [ { text: getLanguageText(cookie, "TERM_USERNAME") }, { text: getLanguageText(cookie, "TERM_REALNAME") },
					{ text: getLanguageText(cookie, "TERM_EMAIL") }, { text: getLanguageText(cookie, "TERM_PHONE") },
					{ text: getLanguageText(cookie, "TERM_LANGUAGE") }, { text: priviligeCodes },
					{ text: getLanguageText(cookie, "BUTTON_CHANGEPASSWORD") } ],
			      items: items,
			      newItem: [ [ createUiTextArea("username", "<username>") ],
					 [ createUiTextArea("realname", "<realname>", 22) ],
					 [ createUiTextArea("email", "<email>", 26) ],
					 [ createUiTextArea("phone", "<phone>", 12) ],
					 [ createUiSelectionList("language", runCallbacByName("datastorageRead" ,"language").languages,
								 runCallbacByName("datastorageRead", "main").main.defaultLanguage, true, false) ],
					 emptyPriviligeList,
					 [ createUiTextNode("password", "") ] ] };
	var email = runCallbacByName("datastorageRead", "email");
	var emailEnabled = runCallbacByName("datastorageRead", "main").main.emailVerification;
	var emailConfigPanel = { title: getLanguageText(cookie, "PROMPT_EMAILADMIN"),
				 frameId: 1,
				 header: [ { text: "" }, { text: "" } ],
				 items: [ [ [ createUiTextNode("email_enabled", getLanguageText(cookie, "TERM_ENABLED")) ],
					    [ createUiCheckBox("email_enabled", emailEnabled, "enabled")] ],
					  [ [ createUiTextNode("mailserver", getLanguageText(cookie, "TERM_MAILSERVER")) ],
					    [ createUiInputField("mailserver", email.host) ] ],
					  [ [ createUiTextNode("username", getLanguageText(cookie, "TERM_USERNAME")) ],
					    [ createUiInputField("username", email.user) ] ],
					  [ [ createUiTextNode("sender", getLanguageText(cookie, "TERM_SENDERADDRESS")) ],
					    [ createUiInputField("sender", email.sender) ] ],
					  [ [ createUiTextNode("password", getLanguageText(cookie, "TERM_PASSWORD")) ],
					    [ createUiInputField("password", email.password, true) ] ],
					  [ [ createUiTextNode("use_ssl", getLanguageText(cookie, "TERM_USESSL")) ],
					    [ createUiCheckBox("use_ssl", email.ssl, "use ssl") ] ],
					  [ [ createUiTextNode("blindly_trust", getLanguageText(cookie, "TERM_BLINDLYTRUST")) ],
					    [ createUiCheckBox("blindly_trust", email.blindlyTrust, "blindly trust") ] ] ] };
					
	var frameList = [ { frameType: "editListFrame", frame: userListPanel },
			  { frameType: "fixedListFrame", frame: emailConfigPanel } ];
	var sendable = { type: "createUiPage",
			 content: { topButtonList: topButtonList,
				    frameList: frameList,
				    buttonList: [ { id: 501, text: "OK", callbackMessage: "saveAdminData" },
						  { id: 502, text: "Cancel",  callbackMessage: "resetToMain" } ] } };
	sendCipherTextToClient(cookie, sendable);
	servicelog("Sent NEW adminData to client #" + cookie.count);
    } else {
	servicelog("User " + cookie.user.username + " does not have Sytem Administration priviliges!");
	processClientStarted(cookie);
    }	
}

function processSaveAdminData(cookie, data) {
    servicelog("Client #" + cookie.count + " requests admin data saving.");
    if(userHasPrivilige("system-admin", cookie.user)) {
	updateAdminDataFromClient(cookie, data);
    } else {
	servicelog("User " + cookie.user.username + " does not have priviliges to edit admin data");
    }
    runCallbacByName("processResetToMainState", cookie);
}

function updateAdminDataFromClient(cookie, userData) {
    var userList = extractUserListFromInputData(userData);
    var emailSettings = extractEmailSettingsFromInputData(userData);
    if(userList === null) {
	runCallbacByName("processResetToMainState", cookie);
	return;
    }
    var newUsers = [];
    var oldUsers = runCallbacByName("datastorageRead", "users").users;
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
    if(runCallbacByName("datastorageWrite", "users", { users: newUsers }) === false) {
	servicelog("User database write failed");
    }
    var main = runCallbacByName("datastorageRead", "main").main;
    main.emailVerification = emailSettings.enabled;
    if(runCallbacByName("datastorageWrite", "main", { main: main }) === false) {
	servicelog("Main database write failed");
    }
    var emailPassword = runCallbacByName("datastorageRead", "email").password;
    var newEmailSettings = { host: emailSettings.host,
			     user: emailSettings.user,
			     sender: emailSettings.sender,
			     password: emailSettings.password,
			     ssl: emailSettings.ssl,
			     blindlyTrust: emailSettings.blindlyTrust };
    if(newEmailSettings.password === "") {
	newEmailSettings.password = emailPassword;
    }
    if(runCallbacByName("datastorageWrite", "email", newEmailSettings) === false) {
	servicelog("Email database write failed");
    }
    servicelog("Updated User database.");
}

function processChangeUserPassword(cookie, data) {
    servicelog("Client #" + cookie.count + " requests user password change.");
    if(userHasPrivilige("system-admin", cookie.user)) {
	var passwordChange = extractPasswordChangeFromInputData(data);
	if(passwordChange === null) {
	    runCallbacByName("processResetToMainState", cookie);
	    return;
	}

	var newUsers = [];
	runCallbacByName("datastorageRead", "users").users.forEach(function(u) {
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
	if(runCallbacByName("datastorageWrite", "users", { users: newUsers }) === false) {
	    servicelog("User database write failed");
	    setStatustoClient(cookie, "Password Change FAILED");
	} else {
	    servicelog("Updated password of user [" + JSON.stringify(passwordChange.userName) + "]");
	    setStatustoClient(cookie, "Password Changed OK");
	    processGainAdminMode(cookie);
	    return;
	}
    } else {
	servicelog("User " + cookie.user.username + " does not have priviliges to change passwords");
    }
    runCallbacByName("processResetToMainState", cookie);
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


// Email related functionality

function generateEmailToken(email) {
    return { mail: sha1.hash(email).slice(0, 8),
	     key: sha1.hash(globalSalt + JSON.stringify(new Date().getTime())).slice(0, 16) };
}

function removePendingEmailRequest(cookie, emailAdress) {
    var pendingUserData = runCallbacByName("datastorageRead", "pending");
    if(Object.keys(pendingUserData.pending).length === 0) {
	servicelog("Empty pending requests database, bailing out");
	return;
    }
    if(pendingUserData.pending.filter(function(u) {
	return u.email === emailAdress;
    }).length !== 0) {
	servicelog("Removing duplicate entry from pending database");
	var newPendingUserData = { pending: [] };
	newPendingUserData.pending = pendingUserData.pending.filter(function(u) {
            return u.email !== emailAdress;
	});
	if(runCallbacByName("datastorageWrite", "pending", newPendingUserData) === false) {
            servicelog("Pending requests database write failed");
	}
    } else {
	servicelog("no duplicate entries in pending database");
    }
}

function getUserByEmail(email) {
    var user = runCallbacByName("datastorageRead", "users").users.filter(function(u) {
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
    if(user != null) {
	return user.username;
    } else {
	return "";
    }
}

function sendVerificationEmail(cookie, recipientAddress) {
    removePendingEmailRequest(cookie, recipientAddress);
    var pendingData = runCallbacByName("datastorageRead", "pending");
    var timeout = new Date();
    var emailToken = generateEmailToken(recipientAddress);
    timeout.setHours(timeout.getHours() + 24);
    var request = { email: recipientAddress,
                    token: emailToken,
                    date: timeout.getTime(),
		    state: "pending" };
    var checksum = sha1.hash(JSON.stringify(request));
    request.checksum = checksum;
    pendingData.pending.push(request);
    if(runCallbacByName("datastorageWrite", "pending", pendingData) === false) {
	servicelog("Pending database write failed");
    }
    if(getUserNameByEmail(recipientAddress) === "") {
	var dummycookie = { user: { language: runCallbacByName("datastorageRead", "main").main.defaultLanguage } };
	var emailSubject = getLanguageText(dummycookie, "EMAILSUBJECT_NEWACCOUNTREQUEST");
	var emailBody = fillTagsInText(getLanguageText(dummycookie, "EMAILBODY_NEWACCOUNTREQUEST"),
				       applicationName,
				       request.token.mail + request.token.key);
    } else {
	var dummycookie = { user: { language: getUserByEmail(recipientAddress).language } };
	var emailSubject = getLanguageText(dummycookie, "EMAILSUBJECT_NEWPASSWORDREQUEST");
	var emailBody = fillTagsInText(getLanguageText(dummycookie, "EMAILBODY_NEWPASSWORDREQUEST"),
				       getUserNameByEmail(recipientAddress),
				       applicationName,
				       request.token.mail + request.token.key);
    }
    var mailDetails = { text: emailBody,
			from: runCallbacByName("datastorageRead", "email").sender,
			to: recipientAddress,
			subject: emailSubject };
    sendEmail(cookie, mailDetails, false, "account verification", false, false);
}

function sendConfirmationEmails(cookie, account) {
    if(account.isNewAccount) {
	var dummycookie = { user: { language: runCallbacByName("datastorageRead", "main").main.defaultLanguage } };
	var emailSubject = getLanguageText(dummycookie, "EMAILSUBJECT_NEWACCOUNTCONFIRM");
	var emailBody = fillTagsInText(getLanguageText(dummycookie, "EMAILBODY_NEWACCOUNTCONFIRM"),
				       account.username,
				       applicationName,
				       runCallbacByName("datastorageRead", "main").main.siteFullUrl);
	var adminEmailSubject = getLanguageText(dummycookie, "EMAILSUBJECT_NEWACCOUNTCREATED");
	var adminEmailBody = fillTagsInText(getLanguageText(dummycookie, "EMAILBODY_NEWACCOUNTCREATED"),
					    account.username,
					    applicationName);
    } else {
	var dummycookie = { user: { language: getUserByEmail(account.email).language } };
	var emailSubject = getLanguageText(dummycookie, "EMAILSUBJECT_NEWPASSWORDCONFIRM");
	var emailBody = fillTagsInText(getLanguageText(dummycookie, "EMAILBODY_NEWPASSWORDCONFIRM"),
				       account.username,
				       applicationName,
				       runCallbacByName("datastorageRead", "main").main.siteFullUrl);
	var adminEmailSubject = getLanguageText(dummycookie, "EMAILSUBJECT_USERHASCHANGEDPASSWORD");
	var adminEmailBody = fillTagsInText(getLanguageText(dummycookie, "EMAILBODY_USERHASCHANGEDPASSWORD"),
					    account.username,
					    applicationName);
    }
    var mailDetails = { text: emailBody,
			from: runCallbacByName("datastorageRead", "email").sender,
			to: account.email,
			subject: emailSubject };
    sendEmail(cookie, mailDetails, false, "account confirmation", false, false);
    var adminUserEmails = runCallbacByName("datastorageRead", "users").users.map(function(u) {
	if(userHasPrivilige("system-admin", u)) { return u.email; }
    }).filter(function(f){return f;}).forEach(function(m) {
	var mailDetails = { text: adminEmailBody,
			    from: runCallbacByName("datastorageRead", "email").sender,
			    to: m,
			    subject: adminEmailSubject };
	sendEmail(cookie, mailDetails, false, "admin confirmation", false, false);
    });
}

function sendEmail(cookie, emailDetails, logline) {
    var emailData = runCallbacByName("datastorageRead", "email");
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
	    setStatustoClient(cookie, "Failed sending email!");
	} else {
	    servicelog("Sent " + logline + " email to " + emailDetails.to);
	    setStatustoClient(cookie, "Sent email");
	}
    });
}


// Language assist functions

function getLanguageText(cookie, tag) {
    if(cookie === null) {
	var language = runCallbacByName("datastorageRead", "main").main.defaultLanguage;
    } else {
	if(cookie.user !== undefined) {
	    var language = cookie.user.language;
	} else {
	    var language = runCallbacByName("datastorageRead", "main").main.defaultLanguage;
	}
    }
    var langData = runCallbacByName("datastorageRead" ,"language");
    var langIndex = langData.languages.indexOf(language);
    if(++langIndex === 0) { return "<no string found>"; }
    if(langData.dictionary.filter(function(f) { return f.tag === tag }).length === 0) { return false; }
    return langData.dictionary.filter(function(f) { return f.tag === tag })[0]["LANG" + langIndex];
}

function fillTagsInText(text) {
    for(var i = 1; i < arguments.length; i++) {
	var substituteString = "_SUBSTITUTE_TEXT_" + i + "_";
	text = text.replace(substituteString, arguments[i]);
    }
    return text;
}

function setApplicationName(name) {
    applicationName = name;
}


// Time out pending email verifications, run once every hour and check for
// entries older than 24 hours.

setInterval(function() {
    var now = new Date().getTime();
    var pendingData = runCallbacByName("datastorageRead", "pending");
    if(Object.keys(pendingData.pending).length === 0) {
	servicelog("No pending requests to purge");
	return;
    }
    var purgeCount = 0
    var newPendingData = { pending: [] };
    pendingData.pending.forEach(function(r) {
	if(r.date < now) {
	    purgeCount++;
	} else {
	    newPendingData.pending.push(r);
	}
    });
    if(purgeCount === 0) {
	servicelog("No pending requests timeouted");
	return;
    } else {
	if(runCallbacByName("datastorageWrite", "pending", newPendingData) === false) {
	    servicelog("Pending requests database write failed");
	} else {
	    servicelog("Removed " + purgeCount + " timeouted pending requests");
	}
    }
}, 1000*60*60);


// Initialize internal datastorages

function initializeDataStorages() {
    runCallbacByName("datastorageInitialize", "main", { main: { version: 1,
								port: 8080,
								siteFullUrl: "http://url.to.my.site/",
								emailVerification: false,
								defaultLanguage: "english" } });
    runCallbacByName("datastorageInitialize", "users", { users: [ { username: "test",
								    hash: sha1.hash("test"),
								    password: getPasswordHash("test", "test"),
								    applicationData: { priviliges: ["system-admin"] },
								    realname: "",
								    email: "",
								    phone: "",
								    language: runCallbacByName("datastorageRead",
											       "main").main.defaultLanguage } ] }, true);
    runCallbacByName("datastorageInitialize", "pending", { pending: [] }, true);
    runCallbacByName("datastorageInitialize", "email", { host: "smtp.your-email.com",
							 user: "username",
							 password: "password",
							 sender: "you <username@your-email.com>",
							 ssl: true,
							 blindlyTrust: true });
    runCallbacByName("datastorageInitialize", "language", { languages: [], dictionary: [] });
}


// Callback to the application specific part handling

var functionList = [];

function setCallback(name, callback) {
    functionList.push({ name: name, function: callback });
}

function runCallbacByName(name, par1, par2, par3, par4, par5) {
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
    if(runCallbacByName("datastorageRead", "language").languages.length === 0) {
	servicelog("ERROR: Missing language definition file!");
	servicelog("Copy the 'language.json' file from framework to './configuration/' directory!");
	servicelog("Exiting program.");
	process.exit(1);
    }
    websocPort = runCallbacByName("datastorageRead", "main").main.port;
    webServer.listen(websocPort, function() {
	servicelog("Waiting for client connection to port " + websocPort + "...");
    });
}

module.exports.startUiLoop = startUiLoop;
module.exports.initializeDataStorages = initializeDataStorages;
module.exports.setCallback = setCallback;
module.exports.setApplicationName = setApplicationName;
module.exports.createUiTextNode = createUiTextNode;
module.exports.createUiTextArea = createUiTextArea;
module.exports.createUiCheckBox = createUiCheckBox;
module.exports.createUiSelectionList = createUiSelectionList;
module.exports.createUiMessageButton = createUiMessageButton;
module.exports.createUiFunctionButton = createUiFunctionButton;
module.exports.createUiInputField = createUiInputField;
module.exports.createUiHtmlCell = createUiHtmlCell;
module.exports.createTopButtons = createTopButtons;
module.exports.getLanguageText = getLanguageText;
module.exports.fillTagsInText = fillTagsInText;
module.exports.sendCipherTextToClient = sendCipherTextToClient;
module.exports.servicelog = servicelog;
module.exports.setStatustoClient = setStatustoClient;
module.exports.userHasPrivilige = userHasPrivilige;
