
# framework

A node.js WebUI framework for easily creating hardened multiuser applications.

## Description

Framework is a module that creates a WebUI frontend for a node.js server that defines the input and output panels running on the client.
The login and authentication process is handled by framework and all communication between the WebUI client and the backend server is encrypted with AES-CTR. 

## Installation

The framework submodule is installed to the server project;
```
git submodule add https://github.com/juiceme/framework.git
git submodule init; git submodule update`
npm install
```

As the server-side user management needs a JSON object storage it is recommended that your project also uses submodule datastorage (https://github.com/juiceme/datastorage.git) and provides the database hooks to the framework.

## Features

* Integrates to JSON data storage like datastorage (https://github.com/juiceme/datastorage.git)
* Handles all communication between the client and server on behalf of the application
* Contains primitives for creating panels and menus based UI
* Uses AES-CTR encryption between server and client to defeat man-in-the-middle attacks.
* Uses and stores only sha1 hashed passwords, plaintext is passwords are unrecoverable in a security breach

## How to start using framework

Go to the `framework/examples/` directory and do `npm install` and run with `node example.js`
Then point your web browser to http://localhost:8080/
Default username is "test" and password is "test"

## Coming soon!

* Probably more enhancements as I think them up :)
    
## Documentation

### User session handling

The session is identified by port connection and stored in a transient cookie in the global cookie list. When user has authenticated the cookie contains the AES key used to encode the transmission between server and client.

### User creation and change management

The user self-creation and management centers on the pending list handling. When an user creates a modifiaction request a corresponding entry is created into the pending list. On completing the modifiaction the entry is purged from the pending list.

The user settings modification dialog reuses the same process and hence an entry is created into the list even though active user sesion is in force and this would not be absolutely necessary.

## REST API description

The server exposes REST API on http://server:port/api/ url. All calls are HTTP POST, if there are no input parameters then an empty list is offered. On the base url http://server:port/ the server returns the client code that calls back to the server API and starts using it. All responses contain at least the result of the operation "result:{result:<errorcode>, text:<explanation>}" 

### Requesting the authentication dialog when a client starts

The client requests a new login panel from the server. The server responds by creating a panel with input fields for username and password and login button. Based on configuration there can be an additional button to request the email verification dialog. This step is optional and used only by the GUI version of the client; when using the server API from scripts or commandline client there is no need to request the authentication dialog panel.
```
client                                            server
------                                            ------
POST //server:port/api/start   -->
     { }
                                           <--   { result: {...},
				                   type: "T_LOGINUIREQUEST",
 	                                           data: { type: "createUiPage",
		                                           content: { frameList: frameList,
				                                      buttonList: buttonList } } }
```

### Passwordless Authentication

The client initiates authentication by sending the sha1sum of the username. If the corresponding username is found, the server responds by creating a session token for further identification of the connection and a new random session key which is encrypted with AES using the stored sha1sum of the user's password.

On receiving the result, the client decrypts the session key using sha1sum of the password queried from the user. The user password or its hash is never sent via the connection, and each connection uses a new session key for further encryption.
```
client                                            server
------                                            ------
POST //server:port/api/login   -->
     { username: <hashedUsername> }
                                           <--   { result: {...},
				                   session: token,
						   type: "T_LOGINGRANTED",
					           serialKey: { serial: serial,
					                        key: sessionKey } }
```

### Requesting the email verification dialog

The client requests the Password Reset / Create User panel from server. The server responds by creating a panel with input fields for email and the verification code, along with buttons to  username and password and login buttonsend tha mail and verify the code. This step is optional and used only by the GUI version of the client; when using the server API from scripts or commandline client there is no need to request the email verification dialog panel.
```
client                                            server
------                                            ------
POST //server:port/api/passwordrecovery   -->
     {}
                                           <--   { result: {...},
                                                   type: "T_VERIFYREQUEST",
	                                           data: { type: "createUiPage",
                                                   content: { frameList: frameList,
				                              buttonList: buttonList } } }
```

### Request Password Reset or New User

The client sends server the email that is used as the user identification key. The server checks if the email address is already associated with an user, and based on this either starts password recovery or new user creation process. An email containing a single-use verification code is generated and sent to the provided address.
```
client                                            server
------                                            ------
POST //server:port/api/sendpasswordemail   -->
     { email:email }
                                           <--   { result: {...} }
```

### Request code verification

The client creates a passcode encrypted by verification code provided by email and sends this message to the server. The server validates the attempt by decrypting the message and responds by creating a panel with input fields for user details and password. If the case is new user creation there is a field for username input, if the case is password recovery, username change is disabled.
```
client                                            server
------                                            ------
POST //server:port/api/validateaccount   -->
     { email: verificationCode.slice(0,8),
       challenge: encrypt("clientValidating",
                           verificationCode.slice(8,24),
                           128) }
                                           <--   { result: {...},
					           type: "T_VERIFYREQUEST",
	                                           data: { type: "createUiPage",
                                                           content: { frameList: frameList,
				                           buttonList: buttonList } } }
```

### Request new user account or user account change

The client sends message with new/modified user details to the server. 
```
client                                            server
------                                            ------
POST //server:port/api/useraccountchange   --->
     { data: encrypt(JSON.stringify( { userData: [ { key: "checksum", value: checksum },
                                                   { key: "isNewAccount", value: boolean },
		                                   { key: "usernameInput", value: username },
		                                   { key: "realnameInput", value: realname },
		                                   { key: "phoneInput", value: phone },
		                                   { key: "languageInput", value: language },
		                                   { key: "passwordInput1", value: password1 },
		                                   { key: "passwordInput2", value: password2 } ] } ),
		     sessionPassword,
		     128) }
                                           <--   { result: {...} }
```

## License

Framework is available under the GPLv3 license.
