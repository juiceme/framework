var site = window.location.hostname;
var mySocket = new WebSocket("ws://" + site + ":" + WEBSOCK_PORT + "/");
var sessionPassword;
var connectionTimerId;

mySocket.onopen = function (event) {
    var sendable = {type:"clientStarted", content:"none"};
    mySocket.send(JSON.stringify(sendable));
    document.getElementById("myStatusField").value = "started";
    connectionTimerId = setTimeout(function() { 
	document.getElementById("myStatusField").value = "No connection to server";
    }, 2000);
};

mySocket.onmessage = function (event) {
    var receivable = JSON.parse(event.data);

//    console.log("Received message: " + JSON.stringify(receivable));

    if(receivable.type == "statusData") {
        document.getElementById("myStatusField").value = receivable.content;
    }

    if(receivable.type == "loginView") {
	var div1 = document.createElement("div");
	document.body.replaceChild(div1, document.getElementById("myDiv1"));
	div1.id = "myDiv1";
	document.body.replaceChild(createLoginView(), document.getElementById("myDiv2"));
	clearTimeout(connectionTimerId);
    }

    if(receivable.type == "payload") {
	// payload is always encrypted, if authentication is not successiful then JSON parsing
	// fails and client is restarted
	try {
	    var content = JSON.parse(Aes.Ctr.decrypt(receivable.content, sessionPassword, 128));
	    defragmentIncomingMessage(content);
	} catch(err) {
	    var sendable = {type:"clientStarted", content:"none"};
	    mySocket.send(JSON.stringify(sendable));
	}
    }
}

var incomingMessageBuffer = "";

function defragmentIncomingMessage(decryptedMessage) {

//    console.log("Decrypted incoming message: " + JSON.stringify(decryptedMessage));

    if(decryptedMessage.type === "nonFragmented") {
	handleIncomingMessage(JSON.parse(decryptedMessage.data));
    }
    if(decryptedMessage.type === "fragment") {
	if(decryptedMessage.id === 0) {
	    incomingMessageBuffer = decryptedMessage.data;
	} else {
	    incomingMessageBuffer = incomingMessageBuffer + decryptedMessage.data;
	}
    }
    if(decryptedMessage.type === "lastFragment") {
	incomingMessageBuffer = incomingMessageBuffer + decryptedMessage.data;
	handleIncomingMessage(JSON.parse(incomingMessageBuffer));
    }
}

function handleIncomingMessage(defragmentedMessage) {

//    console.log("Defragmented incoming message: " + JSON.stringify(defragmentedMessage));

    if(defragmentedMessage.type == "statusData") {
        document.getElementById("myStatusField").value = defragmentedMessage.content;
    }

    if(defragmentedMessage.type == "loginChallenge") {
	var cipheredResponce = Aes.Ctr.encrypt(defragmentedMessage.content, sessionPassword, 128);
	sendToServer("loginResponse", cipheredResponce);
    }

    if(defragmentedMessage.type == "unpriviligedLogin") {
	document.body.replaceChild(createTopButtons(defragmentedMessage.content), document.getElementById("myDiv1"));
	document.body.replaceChild(document.createElement("div"), document.getElementById("myDiv2"));
    }

    if(defragmentedMessage.type == "showTournament") {
	var wnd = window.document.open("about:blank", "", "scrollbars=yes");
	wnd.document.write(defragmentedMessage.content);
	wnd.document.close();
    }

    if(defragmentedMessage.type == "createUiPage") {
	document.body.replaceChild(createTopButtons(defragmentedMessage.content),
				   document.getElementById("myDiv1"));
	document.body.replaceChild(createUiPage(defragmentedMessage.content),
				   document.getElementById("myDiv2"));
    }
}


// ---------- Parse out UI elements from incoming message

function createUiPage(inputData) {
    var fieldset = document.createElement('fieldsetset');
    var id = 2001;

    inputData.frameList.forEach(function(f) {
	fieldset.appendChild(document.createElement('br'));
	if(f.frameType === "fixedListFrame") {
	    fieldset.appendChild(document.createElement('br'));
	    var newFixedItemTable = createFixedItemList(id, inputData, f.frame);
	    id = newFixedItemTable.id;
	    fieldset.appendChild(newFixedItemTable.table);
	    fieldset.appendChild(document.createElement('br'));
	}
	if(f.frameType === "editListFrame") {
	    fieldset.appendChild(document.createElement('br'));
	    var newEditableItemTable = createEditableItemList(id, inputData, f.frame);
	    id = newEditableItemTable.id;
	    fieldset.appendChild(newEditableItemTable.table);
	    fieldset.appendChild(document.createElement('br'));
	}
    });
    fieldset.appendChild(document.createElement('br'));
    if(inputData.buttonList !== undefined) {
	fieldset.appendChild(createAcceptButtons(inputData));
	fieldset.appendChild(document.createElement('br'));
    }

    fieldset.id= "myDiv2";
    return fieldset;

}

function createFixedItemList(id, inputData, frame) {
    var table = document.createElement('table');
    var tableHeader = document.createElement('thead');
    var tableBody = document.createElement('tbody');

    var hRow0 = tableHeader.insertRow();
    var cell = hRow0.insertCell();
    cell.colSpan = frame.header.length + 2;
    cell.innerHTML = "<b>" + frame.title + "</b>";
    var hRow1 = tableHeader.insertRow();
    hRow1.appendChild(document.createElement('td'));
    frame.header.forEach(function(h) {
	var cell= hRow1.insertCell();
	cell.innerHTML = "<b>" + h.text + "</b>";
	hRow1.appendChild(cell);
    });
    var count = 1;
    frame.items.forEach(function(i) {
	var newTableItem = createTableItem(id, count, inputData, i);
	id = newTableItem.id;
	tableBody.appendChild(newTableItem.tableRow);
	count++;
    });
    table.appendChild(tableHeader);
    table.appendChild(tableBody);
    return { id: id, table: table };
}

function createEditableItemList(id, inputData, frame) {
    var table = document.createElement('table');
    var tableHeader = document.createElement('thead');
    var tableBody = document.createElement('tbody');

    var hRow0 = tableHeader.insertRow();
    var cell = hRow0.insertCell();
    cell.colSpan = frame.header.length + 2;
    cell.innerHTML = "<b>" + frame.title + "</b>";
    var hRow1 = tableHeader.insertRow();
    hRow1.appendChild(document.createElement('td'));
    frame.header.forEach(function(h) {
	var cell= hRow1.insertCell();
	cell.innerHTML = "<b>" + h.text + "</b>";
	hRow1.appendChild(cell);
    });
    var count = 1;
    frame.items.forEach(function(i) {
	var newTableItem = createEditTableItem(id, count, inputData, i, frame.frameId, false);
	id = newTableItem.id;
	tableBody.appendChild(newTableItem.tableRow);
	count++;
    });
    var newItem = frame.newItem;
    var newTableItem = createEditTableItem(id, count, inputData, newItem, frame.frameId, true);
    id = newTableItem.id;
    tableBody.appendChild(newTableItem.tableRow);
    table.appendChild(tableHeader);
    table.appendChild(tableBody);
    return { id: id, table: table };
}

function createTopButtons(inputData) {
    var table = document.createElement('table');
    var tableBody = document.createElement('tbody');
    var tableRow = tableBody.insertRow();    

    inputData.topButtonList.forEach(function(b) {
//	var cell = document.createElement('td');
	var button = document.createElement('button');
	button.appendChild(document.createTextNode(b.text));
	button.id = b.id;
	button.onclick = function() {
	    sendToServerEncrypted(b.callbackMessage, inputData);
	    return false;
	};
//	cell.appendChild(button);
	tableRow.appendChild(button);
    });
    table.appendChild(tableBody);
    table.id = "myDiv1";

    return table;
}

function createAcceptButtons(inputData) {
    var table = document.createElement('table');
    var tableBody = document.createElement('tbody');
    var tableRow = tableBody.insertRow();    

    inputData.buttonList.forEach(function(b) {
//	var cell = document.createElement('td');
	var button = document.createElement('button');
	button.appendChild(document.createTextNode(b.text));
	button.id = b.id;
	button.onclick = function() {
	    var freshData = { user: inputData.user,
			      priviliges: inputData.priviliges,
			      items: refreshInputDataItems(inputData, false),
			      buttonList: inputData.buttonList };
	    sendToServerEncrypted(b.callbackMessage, freshData);
	    return false;
	};
//	cell.appendChild(button);
	tableRow.appendChild(button);
    });
    table.appendChild(tableBody);
    return table;
}

function createTableItem(id, count, inputData, item) {
    var tableRow = document.createElement('tr');
    var cell = document.createElement('td');

    cell.appendChild(document.createTextNode(count));
    tableRow.appendChild(cell);
    item.forEach(function(c) {
	var cell = document.createElement('td');
	var newTypedObject = createTypedObject(id, c, inputData);
	id = newTypedObject.id;
	cell.appendChild(newTypedObject.item);
	tableRow.appendChild(cell);
    });
    return { id: id, tableRow: tableRow };
}

function createEditTableItem(id, count, inputData, item, frameId, lastRow) {
    var tableRow = document.createElement('tr');
    var cell = document.createElement('td');

    cell.appendChild(document.createTextNode(count));
    tableRow.appendChild(cell);
    item.forEach(function(c) {
	var cell = document.createElement('td');
	var newTypedObject = createTypedObject(id, c, inputData);
	id = newTypedObject.id;
	cell.appendChild(newTypedObject.item);
	tableRow.appendChild(cell);
    });
    var lastCell = document.createElement('td');
    if(lastRow) {
	var addButton = document.createElement("button");
	addButton.appendChild(document.createTextNode("Luo uusi"));
	addButton.id = count;
	addButton.frameId = frameId;
	addButton.onclick = function() { createNewItemToList(inputData, this); }
	lastCell.appendChild(addButton);
    } else {
	var deleteButton = document.createElement("button");
	deleteButton.appendChild(document.createTextNode("Poista"));
	deleteButton.id = count;
	deleteButton.frameId = frameId;
	deleteButton.onclick = function() { deleteItemFromList(inputData, this); }
	lastCell.appendChild(deleteButton);
    }
    tableRow.appendChild(lastCell);
    return { id: id, tableRow: tableRow };
}

function createNewItemToList(inputData, button) {
    var newItemList = refreshInputDataItems(inputData, true);
    var newFrameList = [];

    inputData.frameList.forEach(function(f) {
	if(f.frame.frameId === button.frameId) {
	    var bottomItem = [];
	    f.frame.newItem.forEach(function(i) {
		bottomItem.push(getTypedObjectTemplateById(i, true));
	    });
	    newItemList[button.frameId].frame.push(bottomItem);
	    var newFrame = { title: f.frame.title,
			     frameId: f.frame.frameId,
			     header: f.frame.header,
			     items: newItemList[button.frameId].frame,
			     newItem: f.frame.newItem };
	    newFrameList.push({ frameType: f.frameType,
				frame: newFrame });
	} else {
	    newFrameList.push(f);
	}
    });
    var newData = { user: inputData.user,
		    priviliges: inputData.priviliges,
		    topButtonList: inputData.topButtonList,
		    frameList: newFrameList,
		    buttonList: inputData.buttonList };

    document.body.replaceChild(createUiPage(newData),
			       document.getElementById("myDiv2"));
    return false;
}

function deleteItemFromList(inputData, button) {
    var newFrameList = [];

    inputData.frameList.forEach(function(f) {
	if(f.frame.frameId !== button.frameId) {
	    newFrameList.push(f);
	} else {
	    var newItems = [];
	    var count = 1;
	    f.frame.items.forEach(function(i) {
		if(count++ !== parseInt(button.id)) {
		    newItems.push(i);
		}
	    });
	    newFrameList.push( { frameType: f.frameType,
				 frame: { title: f.frame.title,
			 		  frameId: f.frame.frameId,
					  header: f.frame.header,
					  items: newItems,
					  newItem: f.frame.newItem } });
	}
    });
    inputData.frameList = newFrameList;

    document.body.replaceChild(createUiPage(inputData),
			       document.getElementById("myDiv2"));
    return false;
}

function refreshInputDataItems(inputData, fullData) {
    var newItemList = [];
    inputData.frameList.forEach(function(f) {
	var newFrameList = [];
        f.frame.items.forEach(function(g) {
            var newFrame = [];
            g.forEach(function(i) {
		newFrame.push(getTypedObjectTemplateById(i, fullData));
            });
            newFrameList.push(newFrame);
        });
	newItemList.push({ frameType: f.frameType,
			   frameId: f.frame.frameId,
                           frame: newFrameList });
    });
    return newItemList;
}

function createTypedObject(id, item, inputData) {
    var newItemContainer = document.createElement('div');

    item.forEach(function(i) {
	if(i.itemType === "textnode") {
	    var newItem = document.createElement('div');
	    newItem.itemType = "textnode";
	    newItem.key = i.key;
	    newItem.id = id++;
	    i.itemId = newItem.id;
	    newItem.itemText = i.text;
	    newItem.appendChild(document.createTextNode(i.text));
	    newItemContainer.appendChild(newItem);
	}

	if(i.itemType === "textarea") {
	    var newItem = document.createElement("textarea");
	    newItem.itemType = "textarea";
	    newItem.key = i.key;
	    newItem.id = id++;
	    i.itemId = newItem.id;
	    newItem.setAttribute('cols', i.cols);
	    newItem.setAttribute('rows', i.rows);
	    newItem.value = i.value;
	    newItemContainer.appendChild(newItem);
	}

	if(i.itemType === "checkbox") {
	    var newItem = document.createElement('input');
	    newItem.itemType = "checkbox";
	    newItem.key = i.key;
	    newItem.type = "checkbox";
	    if(!i.active) {
		newItem.disabled = "disabled";
	    }
	    newItem.id = id++;
	    i.itemId = newItem.id;
	    newItem.checked = i.checked;
	    newItem.title = i.title;
	    newItemContainer.appendChild(newItem);
	}

	if(i.itemType === "selection") {
	    var newItem = document.createElement('select');
	    var myOption = document.createElement('option');
	    var literalList = [];
	    var zeroOption = { text: "", item: "", value: 0 };
	    myOption.text = "";
	    myOption.item = "";
	    myOption.value = 0;
	    if(!i.active) {
		newItem.disabled = true;
	    }
	    literalList.push(zeroOption);
	    newItem.add(myOption);
	    var count = 1;
	    i.list.forEach(function(j) {
		var myOption = document.createElement('option');
		var nOption = { text: j.text, item: j.item, value: count };
		myOption.text = j.text;
		myOption.item = j.item;
		myOption.value = count;
		literalList.push(nOption);
		newItem.add(myOption);
		count++;
	    });
	    newItem.itemType = "selection";
	    newItem.key = i.key;
	    newItem.id = id++;
	    i.itemId = newItem.id;
	    newItem.literalList = literalList;
	    setSelectedItemInList(newItem, i.selected);
	    newItemContainer.appendChild(newItem);
	}

	if(i.itemType === "button") {
	    var newItem = document.createElement('div');
	    newItem.itemType = "button";
	    newItem.id = id++;
	    i.itemId = newItem.id;
	    newItem.text = i.text;
	    newItem.callbackMessage = i.callbackMessage;
	    var button = document.createElement('button');
	    if(!i.active) {
		button.disabled = true;
	    }
	    button.appendChild(document.createTextNode(i.text));
	    button.onclick = function() { sendToServerEncrypted(i.callbackMessage,
								{ buttonId: i.itemId,
								  buttonData: i.data,
								  items: refreshInputDataItems(inputData, false) });
					  return false;
					};
	    newItem.appendChild(button);
	    newItemContainer.appendChild(newItem);
	}

	if(i.itemType === "input") {
	    var newItem = document.createElement('input');
	    newItem.itemType = "input";
	    newItem.key = i.key;
	    if(i.password === false) {
		newItem.type = "text";
		newItem.value = i.value;
	    } else {
		newItem.type = "password";
	    }
	    newItem.id = id++;
	    i.itemId = newItem.id;
	    newItemContainer.appendChild(newItem);
	}

    });

    return { id: id, item: newItemContainer };
}

function setSelectedItemInList(myList, myItem) {
    myList.selectedIndex = Object.keys(myList).map(function(a) {
       if(JSON.stringify(myList[a].item) === JSON.stringify(myItem)) return a;
    }).filter(function(f) {
       return f;
    })[0];
}

function getSelectedItemInList(selectionList) {
    return  selectionList.options[selectionList.selectedIndex].item;
}

function getTypedObjectTemplateById(item, fullData) {
    var itemList = [];

    item.forEach(function(i) {
	var uiItem = document.getElementById(i.itemId);

	if(i.itemType === "textnode") {
	    itemList.push( { itemType: "textnode",
			     key: i.key,
			     text: uiItem.itemText } );
	}
	if(i.itemType === "textarea") {
	    itemList.push( { itemType: "textarea",
			     key: i.key,
			     value: uiItem.value,
			     cols: i.cols,
			     rows: i.rows,
			     password: i.password } );
	}
	if(i.itemType === "checkbox") {
	    itemList.push( { itemType: "checkbox",
			     key: i.key,
			     checked: uiItem.checked,
			     title: i.title,
			     active: i.active } );
	}
	if(i.itemType === "selection") {
	    var newSelector = { itemType: "selection",
				key: i.key,
				selected: getSelectedItemInList(uiItem),
				active: i.active };
	    if(fullData) { newSelector.list = i.list; }
	    itemList.push(newSelector);
	}
	if(i.itemType === "button") {
	    itemList.push( { itemType: "button",
			     text: i.text,
			     itemId: i.itemId,
			     data: i.data,
			     callbackMessage: i.callbackMessage,
			     active: i.active } );
	}
	if(i.itemType === "input") {
	    itemList.push( { itemType: "input",
			     key: i.key,
			     value: uiItem.value,
			     password: i.password } );
	}
    });

    return itemList;
}



// ---------- Utility helper functions



function sendLogin(username, password) {
    div = document.createElement('div');
    div.id = "myDiv2";
    document.body.replaceChild(div, document.getElementById("myDiv2"));
    sessionPassword = Sha1.hash(password + Sha1.hash(username).slice(0,4));
    sendToServer("userLogin", { username: Sha1.hash(username) });
//    console.log("SessionPassword = " + sessionPassword);
}

function uiText(text) {
    return decodeURIComponent(escape(text));
}

function setElementStyle(element) {
    element.style.border = "solid #ffffff";
    element.style.padding = "0";
}

function sendToServer(type, content) {
    var sendable = { type: type, content: content };
    mySocket.send(JSON.stringify(sendable));
}

function sendFragment(type, id, data) {
    var fragment = JSON.stringify({ type: type, id: id, length: data.length, data: data });
    var cipherSendable = JSON.stringify({ type: "payload",
					  content: Aes.Ctr.encrypt(fragment, sessionPassword, 128) });
    mySocket.send(cipherSendable);
}

var fragmentSize = 10000;

function sendToServerEncrypted(type, content) {
    var sendableString = JSON.stringify({ type: type, content: content });
    var count = 0;
    var originalLength = sendableString.length;
    if(sendableString.length <= fragmentSize) {
	sendFragment("nonFragmented", count++, sendableString);
    } else {
	while(sendableString.length > fragmentSize) {
	    sendableStringFragment = sendableString.slice(0, fragmentSize);
	    sendableString = sendableString.slice(fragmentSize, sendableString.length);
	    sendFragment("fragment", count++, sendableStringFragment);
	}
	if(sendableString.length > 0) {
	    sendFragment("lastFragment", count++, sendableString);
	}
    }
//    console.log("Sent " + originalLength + " bytes in " + count + " fragments to server");
}


// ---------- Login panel handling

function createLoginView() {
    var table = document.createElement('table');
    var tHeader = document.createElement('thead');
    var tBody = document.createElement('tbody');
    var hRow = document.createElement('tr');
    var hCell = document.createElement('td');
    var bRow1 = document.createElement('tr');
    var bCell1a = document.createElement('td');
    var bCell1b = document.createElement('td');
    var bRow2 = document.createElement('tr');
    var bCell2a = document.createElement('td');
    var bCell2b = document.createElement('td');
    var bRow3 = document.createElement('tr');
    var bCell3a = document.createElement('td');
    var bCell3b = document.createElement('td');
    var bRow4 = document.createElement('tr');
    var bCell4a = document.createElement('td');
    var bCell4b = document.createElement('td');
    var bRow5 = document.createElement('tr');
    var bCell5a = document.createElement('td');
    var bCell5b = document.createElement('td');

    var usernameField = document.createElement("input");
    var passwordField = document.createElement("input");
    var loginButton = document.createElement("button");

    usernameField.name="username";
    usernameField.type="text"
    passwordField.name="password";
    passwordField.type="password";

    hCell.colSpan = "2";
    hCell.appendChild(document.createTextNode(uiText("Kirjaudu sisään turnaustilastooon")));
    hRow.appendChild(hCell);
    setElementStyle(hCell);
    tHeader.appendChild(hRow);
    table.appendChild(tHeader);

    bCell1a.style.border = "solid #ffffff";
    bCell1b.style.border = "solid #ffffff";
    setElementStyle(bCell2a);
    setElementStyle(bCell2b);
    setElementStyle(bCell3a);
    setElementStyle(bCell3b);
    bCell4a.style.border = "solid #ffffff";
    bCell4b.style.border = "solid #ffffff";
    setElementStyle(bCell5a);
    setElementStyle(bCell5b);

    bCell1a.appendChild(document.createTextNode(" "));
    bCell2a.appendChild(document.createTextNode(uiText("Käyttäjä") + ": "));
    bCell2b.appendChild(usernameField);
    bCell3a.appendChild(document.createTextNode("Salasana" + ": "));
    bCell3b.appendChild(passwordField);
    bCell4a.appendChild(document.createTextNode(" "));

    loginButton.appendChild(document.createTextNode("Kirjaudu"));
    loginButton.onclick = function() { sendLogin(usernameField.value, passwordField.value); }

    bCell5a.appendChild(loginButton);

    bRow1.appendChild(bCell1a);
    bRow1.appendChild(bCell1b);
    bRow2.appendChild(bCell2a);
    bRow2.appendChild(bCell2b);
    bRow3.appendChild(bCell3a);
    bRow3.appendChild(bCell3b);
    bRow4.appendChild(bCell4a);
    bRow4.appendChild(bCell4b);
    bRow5.appendChild(bCell5a);
    bRow5.appendChild(bCell5b);

    tBody.appendChild(bRow1);
    tBody.appendChild(bRow2);
    tBody.appendChild(bRow3);
    tBody.appendChild(bRow4);
    tBody.appendChild(bRow5);

    table.appendChild(tBody);
    table.id = "myDiv2";

    return table;
}
