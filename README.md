
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

None whatsoever :)

## License

Framework is available under the GPLv3 license.
