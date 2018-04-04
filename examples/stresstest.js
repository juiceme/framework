var websocketClient = require("websocket").client;
var mySocket = new websocketClient();
var sha1 = require('./framework/crypto/sha1.js');
var Aes = require('./framework/crypto/aes.js');
Aes.Ctr = require('./framework/crypto/aes-ctr.js');

var myConnection;
var sessionPassword;

function sendToServer(type, content) {
    var sendable = { type: type, content: content };
    myConnection.send(JSON.stringify(sendable));
}

mySocket.on('connectFailed', function(error) {
    console.log('Connect Error: ' + error.toString());
});

mySocket.on('connect', function(connection) {
    console.log('WebSocket Client Connected');
    connection.on('error', function(error) {
        console.log("Connection Error: " + error.toString());
    });
    connection.on('close', function() {
        console.log('echo-protocol Connection Closed');
    });
    connection.on('message', function(message) {
        if (message.type !== 'utf8') {
            console.log("Received non-utf8 message: " + JSON.stringify(message));
        } else {
//	    console.log("Received message: " + JSON.stringify(message.utf8Data));
	    var receivable = JSON.parse(message.utf8Data);
	    if(receivable.type === "createUiPage") {
		// login screen is the only object sent over plaintext.
		// use default credentials of test-user
		sessionPassword=sha1.hash("test" + sha1.hash("test").slice(0,4));
		sendToServer('userLogin', { username: sha1.hash("test") });
	    }
	    if(receivable.type === "payload") {
		// don't bother to defragment, it's comin in as a single packet anyway
		var content = JSON.parse(Aes.Ctr.decrypt(receivable.content, sessionPassword, 128));
//		console.log("Received encrypted message: " + JSON.stringify(content));
		processIncomingMessage(content);
	    }
	}

    });
    
    if (connection.connected) {
	myConnection = connection;
	var sendable = {type:"clientStarted", content:"none"};
	myConnection.send(JSON.stringify(sendable));      
    }
});

function processIncomingMessage(content) {
    var message = JSON.parse(content.data);
    if(message.type === "loginChallenge") {
	console.log("Logging in...");
	var cipheredResponce = Aes.Ctr.encrypt(message.content, sessionPassword, 128);
	sendToServer("loginResponse", cipheredResponce);
    }
    if(message.type === "createUiPage") {
	console.log("Logged in as \"test\"");
    }
}


setInterval(function() {
    mySocket.connect('ws://localhost:8080/');
}, 100);



