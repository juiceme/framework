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

    var itemList = { title: "Please Login:",
                     frameId: 0,
                     header: [ { text: "" }, { text: "" } ],
		     rowNumbers: false,
                     items: [ [ [ createUiTextNode("username", "Username:") ],
                                [ createUiInputField("userNameInput", "", false) ] ],
			      [ [ createUiTextNode("password", "Password:") ],
				[ createUiInputField("passwordInput", "", true) ] ] ] };
    var frameList = [ { frameType: "fixedListFrame", frame: itemList } ];
    var sendable = { type: "createUiPage",
                     content: { frameList: frameList,
				buttonList: [ { id: 501,
						text: "Login",
						callbackFunction: "var username=''; var password=''; document.querySelectorAll('input').forEach(function(i){ if(i.key === 'userNameInput') { username = i.value; }; if(i.key === 'passwordInput') { password = i.value; }; }); sessionPassword=Sha1.hash(password + Sha1.hash(username).slice(0,4)); sendToServer('userLogin', { username: Sha1.hash(username) } ); return false;" },
					      { id: 502,
						text: "Create new account / Change passsword",
						callbackFunction: "sessionPassword=''; sendToServer('createOrModifyAccount', {}); return false;" } ] } };
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
    var itemList = { title: "Create new account or modify existing:",
                     frameId: 0,
                     header: [ { text: "" }, { text: "" }, { text: "" } ],
		     rowNumbers: false,
                     items: [ [ [ createUiTextNode("email", "Email:") ],
                                [ createUiInputField("emailInput", "", false) ],
				[ createUiFunctionButton("Send Email!", "var email=''; document.querySelectorAll('input').forEach(function(i){ if(i.key === 'emailInput') { email = i.value; }; }); sendToServer('accountRequestMessage', {email:email}); return false;") ] ],
			      [ [ createUiTextNode("verification", "Verification code:") ],
				[ createUiInputField("verificationInput", "", false) ],
				[ createUiFunctionButton("Validate Account!", "var code=''; document.querySelectorAll('input').forEach(function(i){ if(i.key === 'verificationInput') { code = i.value; }; }); sessionPassword = code.slice(8,24); sendToServer('validateAccountMessage', { email: code.slice(0,8), challenge: Aes.Ctr.encrypt('clientValidating', sessionPassword, 128) });") ] ] ] };
    var frameList = [ { frameType: "fixedListFrame", frame: itemList } ];
    var sendable = { type: "createUiPage",
                     content: { frameList: frameList,
				buttonList: [ { id: 501,
						text: "Cancel",
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
	var newAccount = { isNewAccount: true,
			   email: account.email,
			   username: "",
			   realname: "",
			   phone: "" };
	var user = getUserByEmail(account.email);
	if(user !== null) {
	    newAccount.isNewAccount = false;
	    newAccount.username = user.username;
	    newAccount.realname = user.realname;
	    newAccount.phone = user.phone;
	    setState(cookie, "oldUserValidated");
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
    } else {
	var newPendingUserData = [];
	newPendingUserData = pendingUserData.filter(function(u) {
	    return u.token.mail !== emailHash.slice(0, 8);
	});

	if(runCallbacByName("datastorageWrite", "pending", { pending: newPendingUserData }) === false) {
	    servicelog("Pending requests database write failed");
	} else {
	    servicelog("Removed pending request from database");
	}
	return target[0];
    }
}

function sendUserAccountModificationDialog(cookie, account) {
    var title = "";
    var items = [];
    items.push([ [ createUiTextNode("email", "Email:") ], [ createUiInputField("emailInput", account.email, false) ] ]);
    if(account.isNewAccount) {
	title = "Create new account:";
	items.push([ [ createUiTextNode("username", "Username:") ], [ createUiInputField("usernameInput", account.username, false) ] ]);
    } else {
	title = "Modify your account:";
	items.push([ [ createUiTextNode("username", "Username:") ], [ createUiInputField("usernameInput", account.username, false, true) ] ]);
    }
    items.push([ [ createUiTextNode("realname", "Realname:") ], [ createUiInputField("realnameInput", account.realname, false) ] ]);
    items.push([ [ createUiTextNode("phone", "Phone:") ], [ createUiInputField("phoneInput", account.phone, false) ] ]);
    items.push([ [ createUiTextNode("password1", "Password:") ], [ createUiInputField("passwordInput1", "", true) ] ]);
    items.push([ [ createUiTextNode("password2", "Repeat password:") ], [ createUiInputField("passwordInput2", "", true) ] ]);

    var itemList = { title: title,
                     frameId: 0,
                     header: [ { text: "" }, { text: "" } ],
		     rowNumbers: false,
                     items: items };
    var frameList = [ { frameType: "fixedListFrame", frame: itemList } ];
    var sendable = { type: "createUiPage",
                     content: { frameList: frameList,
				buttonList: [ { id: 501,
						text: "Cancel",
						callbackFunction: "sessionPassword=''; sendToServer('clientStarted', {}); return false;" },
					      { id: 502,
						text: "OK",
						callbackFunction: "var userData=[{ key:'isNewAccount', value:" + account.isNewAccount + " }]; document.querySelectorAll('input').forEach(function(i){ if(i.key != undefined) { userData.push({ key:i.key, value:i.value } ); } }); sendToServerEncrypted('userAccountChangeMessage', { userData: userData } ); return false;" } ] } };
    sendCipherTextToClient(cookie, sendable);
    setStatustoClient(cookie, "Modify account");
}

function processUserAccountChangeMessage(cookie, content) {
    if(content.userData === undefined) {
	servicelog("User account change contains no data.");
	processClientStarted(cookie);
	return;
    }
    var account = { isNewAccount: findObjectByKey(content.userData, "key", "isNewAccount").value,
		    email: findObjectByKey(content.userData, "key", "emailInput").value,
		    username: findObjectByKey(content.userData, "key", "usernameInput").value,
		    realname: findObjectByKey(content.userData, "key", "realnameInput").value,
		    phone: findObjectByKey(content.userData, "key", "phoneInput").value };
    if(findObjectByKey(content.userData, "key", "passwordInput1").value != findObjectByKey(content.userData, "key", "passwordInput2").value) {
	sendUserAccountModificationDialog(cookie, account);
	setStatustoClient(cookie, "Password mismatch!");
	servicelog("Password mismatch in account change dialog");
    } else {
	account.password = findObjectByKey(content.userData, "key", "passwordInput1").value;
	changeUserAccount(cookie, account);
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

function createUiSelectionList(key, list, selected, active) {
    var listItems = list.map(function(i) {
	return { text: i, item: i }
    }).filter(function(f) { return f; });
    if(active === undefined) { active = true; }
    return { itemType: "selection", key: key, list: listItems, selected: selected, active: active };
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
}


// Anminstration UI panel

function processGainAdminMode(cookie, content) {
    servicelog("Client #" + cookie.count + " requests Sytem Administration priviliges");
    if(userHasPrivilige("system-admin", cookie.user)) {
	servicelog("Granting Sytem Administration priviliges to user " + cookie.user.username);
	var topButtonList =  createTopButtons(cookie, true);
	var items = [];
	var priviligeList = runCallbacByName("createAdminPanelUserPriviliges");
	runCallbacByName("datastorageRead", "users").users.forEach(function(u) {
	    var userPriviliges = [];
	    priviligeList.forEach(function(p) {
		userPriviliges.push(createUiCheckBox(p.privilige, userHasPrivilige(p.privilige, u), p.code));
	    });
	    items.push([ [ createUiTextNode("username", u.username) ],
			 [ createUiTextArea("realname", u.realname, 25) ],
			 [ createUiTextArea("email", u.email, 30) ],
			 [ createUiTextArea("phone", u.phone, 15) ],
			 userPriviliges,
		         [ createUiMessageButton("Change", "changeUserPassword", u.username),
			   createUiInputField("password", "", true) ] ] )
	});
	var emptyPriviligeList = [];
	priviligeList.forEach(function(p) {
	    emptyPriviligeList.push(createUiCheckBox(p.privilige, false, p.code));
	});
        var priviligeCodes = "";
        runCallbacByName("createAdminPanelUserPriviliges").forEach(function(p) {
            priviligeCodes = priviligeCodes + p.code + " / ";
        });
        priviligeCodes = priviligeCodes.slice(0, priviligeCodes.length-3);
	var itemList = { title: "User Admin Data",
			 frameId: 0,
			 header: [ { text: "username" }, { text: "realname" }, { text: "email" },
				   { text: "phone" }, { text: priviligeCodes }, { text: "Change Password" } ],
			 items: items,
			 newItem: [ [ createUiTextArea("username", "<username>") ],
				    [ createUiTextArea("realname", "<realname>", 25) ],
				    [ createUiTextArea("email", "<email>", 30) ],
				    [ createUiTextArea("phone", "<phone>", 15) ],
				    emptyPriviligeList,
				    [ createUiTextNode("password", "") ] ] };
	var frameList = [ { frameType: "editListFrame", frame: itemList } ];
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
    } else {
	servicelog("Updated User database.");
    }
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
	servicelog("inputDataata does not contain items");
	return null;
    }
    if(data.buttonList === undefined) {
	servicelog("inputData does not contain buttonList");
	return null;
    }
    var userList = [];
    data.items.forEach(function(i) {
	i.frame.forEach(function(u) {
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
		} else {
		    var priviligeList = runCallbacByName("createAdminPanelUserPriviliges").map(function(p) {
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
    });
    return userList;
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
		     password: getPasswordHash(u[0][0].text, u[5][1].value) };
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
    var emailData = runCallbacByName("datastorageRead", "email");
    var timeout = new Date();
    var emailToken = generateEmailToken(recipientAddress);
    timeout.setHours(timeout.getHours() + 24);
    var request = { email: recipientAddress,
                    token: emailToken,
                    date: timeout.getTime() };
    pendingData.pending.push(request);
    if(runCallbacByName("datastorageWrite", "pending", pendingData) === false) {
	servicelog("Pending database write failed");
    }
    if(getUserNameByEmail(recipientAddress) === "") {
	var emailSubject = "You have requested a new account";
	var emailBody = "\r\nYou have requested a new user account of xxxxxxxx.\r\n\r\nCopy the following code to the \"validation code\" field and push \"Validate Account!\" button.\r\nYour validation code: " + request.token.mail + request.token.key + "\r\n\r\nThe above code is valid for 24 hours.\r\n\r\n   -Administrator-\r\n";
    } else {
	var emailSubject = "Your new password for xxxxxxxx"
	var emailBody = "\r\nHello " + getUserNameByEmail(recipientAddress) + ", you have requested a password reset of your xxxxxxxx account.\r\n\r\nCopy the following code to the \"validation code\" field and push \"Validate Account!\" button.\r\nYour validation code: " + request.token.mail + request.token.key + "\r\n\r\nThe above code is valid for 24 hours.\r\n\r\n   -Administrator-\r\n"
    }
    var mailDetails = { text: emailBody,
			from: emailData.sender,
			to: recipientAddress,
			subject: emailSubject };

    sendEmail(cookie, mailDetails, false, "account verification", false, false);
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
    return null;
}

function startUiLoop(port) {
    websocPort = port;
    webServer.listen(port, function() {
	servicelog("Waiting for client connection to port " + port + "...");
    });
}

module.exports.startUiLoop = startUiLoop;
module.exports.setCallback = setCallback;
module.exports.createUiTextNode = createUiTextNode;
module.exports.createUiTextArea = createUiTextArea;
module.exports.createUiCheckBox = createUiCheckBox;
module.exports.createUiSelectionList = createUiSelectionList;
module.exports.createUiMessageButton = createUiMessageButton;
module.exports.createUiFunctionButton = createUiFunctionButton;
module.exports.createUiInputField = createUiInputField;
module.exports.createTopButtons = createTopButtons;
module.exports.sendCipherTextToClient = sendCipherTextToClient;
module.exports.servicelog = servicelog;
module.exports.setStatustoClient = setStatustoClient;
module.exports.userHasPrivilige = userHasPrivilige;
module.exports.getPasswordHash = getPasswordHash;
module.exports.sha1 = sha1.hash;
module.exports.aes = Aes.Ctr;
