var websocket = require("websocket");
var http = require("http");
var fs = require("fs");
var Aes = require('./crypto/aes.js');
Aes.Ctr = require('./crypto/aes-ctr.js');
var sha1 = require('./crypto/sha1.js');

var websocPort = 0;
var globalSalt = sha1.hash(JSON.stringify(new Date().getTime()));
var databaseVersion = 3;
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
    var clienthead = fs.readFileSync("./clienthead", "utf8");
    var variables = getClientVariables();
    var clientbody = fs.readFileSync("./client.js", "utf8");
    var aesjs = fs.readFileSync("./crypto/aes.js", "utf8");
    var aesctrjs = fs.readFileSync("./crypto/aes-ctr.js", "utf8");
    var sha1js = fs.readFileSync("./crypto/sha1.js", "utf8");
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
	    if(type === "loginResponse") { processLoginResponse(cookie, content); }
	    if(type === "payload") {
		try {
		    var decryptedMessage = JSON.parse(Aes.Ctr.decrypt(content, cookie.user.password, 128));
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
    var sendable = { type: "loginView" }
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
    var plainResponse = Aes.Ctr.decrypt(content, cookie.user.password, 128);
    if(cookie.challenge === plainResponse) {
	servicelog("User login OK");
	setState(cookie, "loggedIn");
	setStatustoClient(cookie, "Login OK");
	if(getUserPriviliges(cookie.user).length === 0) {
	    // for unpriviliged login, only send logout button and nothing more
	    sendable = { type: "unpriviligedLogin",
			 content: { topButtonList: [ { id: 100,
						       text: "Kirjaudu Ulos",
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

function createUiButton(text, callbackMessage, data, active) {
    if(active === undefined) { active = true; }
    return { itemType: "button", text: text, callbackMessage: callbackMessage, data: data, active: active };
}

function createUiInputField(key, value, password) {
    if(password  === undefined) { password = false; }
    return { itemType: "input", key: key, value: value, password: password };
}


// Anminstration UI panel

function processGainAdminMode(cookie, content) {
    servicelog("Client #" + cookie.count + " requests Sytem Administration priviliges");
    if(userHasPrivilige("system-admin", cookie.user)) {
	servicelog("Granting Sytem Administration priviliges to user " + cookie.user.username);
	var sendable;
	var topButtonList =  runCallbacByName("createTopButtonList", cookie, true);

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
		         [ createUiButton("Vaihda", "changeUserPassword", u.username),
			   createUiInputField("password", "", true) ] ] )
	});

	var emptyPriviligeList = [];
	priviligeList.forEach(function(p) {
	    emptyPriviligeList.push(createUiCheckBox(p.privilige, false, p.code));
	});
	var itemList = { title: "User Admin Data",
			 frameId: 0,
			 header: [ { text: "username" }, { text: "realname" }, { text: "email" },
				   { text: "phone" }, { text: "V / S / Te / Pe / To / A" }, { text: "Vaihda Salasana" } ],
			 items: items,
			 newItem: [ [ createUiTextArea("username", "<username>") ],
				    [ createUiTextArea("realname", "<realname>", 25) ],
				    [ createUiTextArea("email", "<email>", 30) ],
				    [ createUiTextArea("phone", "<phone>", 15) ],
				    emptyPriviligeList,
				    [ createUiTextNode("password", "") ] ] };

	var frameList = [ { frameType: "editListFrame", frame: itemList } ];

	sendable = { type: "createUiPage",
		     content: { user: cookie.user.username,
				priviliges: cookie.user.applicationData.priviliges,
				topButtonList: topButtonList,
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
module.exports.createUiButton = createUiButton;
module.exports.createUiInputField = createUiInputField;
module.exports.sendCipherTextToClient = sendCipherTextToClient;
module.exports.servicelog = servicelog;
module.exports.setStatustoClient = setStatustoClient;
module.exports.userHasPrivilige = userHasPrivilige;
module.exports.getPasswordHash = getPasswordHash;
module.exports.sha1 = sha1.hash;
module.exports.aes = Aes.Ctr;
