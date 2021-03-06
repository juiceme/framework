var site = window.location.hostname;
var connectionTimerId;
var sessionToken = "";
var sessionKey = "";
var sessionSerial = "";

if(window.NodeList && !NodeList.prototype.forEach) {
    NodeList.prototype.forEach = function(callback, thisArg) {
        thisArg = thisArg || window;
        for(var i = 0; i < this.length; i++) {
            callback.call(thisArg, this[i], i, this);
        }
    };
}

function postData(restPath, data) {
    var xhr = new XMLHttpRequest();
    url = "http://" + site + ":" + LISTEN_PORT + restPath;
    xhr.open("POST", url, true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onreadystatechange = function () {
	if (xhr.readyState === 4 && xhr.status === 200) {
	    try {
		var data = JSON.parse(xhr.responseText);
		processRestReplyMessage(data);
	    } catch(err) {
		console.log("Received illegal api call: " + err);
//		postData("/api/start", {});
	    }
	}
    };
    xhr.send(JSON.stringify(data));
}

function postEncrypted(url, data) {
    sessionSerial++;
    var serialTokenData = { serial: sessionSerial,
			    token: sessionToken,
			    data: data };
    postData(url, { token: sessionToken,
		    data: Aes.Ctr.encrypt(JSON.stringify(serialTokenData), sessionKey, 128) });
}

function displayMessage(message) {
    document.getElementById("myStatusField").value = message;
}

setInterval(function() {
    // if loggedin, poll server every 10 seconds
    if(sessionKey !== "") {
	postEncrypted('/api/poll', {});
    }
}, 1000*10);

// this requests the login screen with a REST call
postData("/api/start", {});
connectionTimerId = setTimeout(function() {
    document.getElementById("myStatusField").value = "No connection to server";
}, 2000);

// main client message loop
function processRestReplyMessage(data) {
    if(data.result.result === "E_OK") {
	clearTimeout(connectionTimerId);
	if((data.type === "T_LOGINUI") ||
	   (data.type === "T_VERIFYUI")) {
	    // messages are not encrypted
	    if(data.data.type === "createUiPage") {
		// top buttons are not defined
		var div1 = document.createElement("div");
		document.body.replaceChild(div1, document.getElementById("myDiv1"));
		div1.id = "myDiv1";
		document.body.replaceChild(createUiPage(data.data.content),
					   document.getElementById("myDiv2"));
		displayMessage(data.message);
	    }
	}
	if(data.type === "T_USERMODIFICATIONUI") {
	    userModificationData = JSON.parse(Aes.Ctr.decrypt(data.data,
							      sessionKey, 128));
	    if(userModificationData.type === "createUiPage") {
		// user modification panel has no top buttons
		var div1 = document.createElement("div");
		document.body.replaceChild(div1, document.getElementById("myDiv1"));
		div1.id = "myDiv1";
		document.body.replaceChild(createUiPage(userModificationData.content),
					   document.getElementById("myDiv2"));
		displayMessage(data.message);
	    }
	}
	if(data.type === "T_LOGIN") {
	    displayMessage(data.message);
	    sessionToken = data.token;
	    serialKey = JSON.parse(Aes.Ctr.decrypt(data.serialKey, sessionKey, 128));
	    sessionKey = serialKey.key;
	    sessionSerial = serialKey.serial;
	    postEncrypted("/api/window/0", {});
	}
	if(data.type === "T_UIWINDOWREQUEST") {
	    displayMessage(data.message);
	    var data = JSON.parse(Aes.Ctr.decrypt(data.data, sessionKey, 128));
	    if(data.type == "unpriviligedLogin") {
		var div = document.createElement('div');
		div.id = "myDiv2";
		document.body.replaceChild(createTopButtons(data.content),
					   document.getElementById("myDiv1"));
		document.body.replaceChild(div, document.getElementById("myDiv2"));
	    }
	    if(data.type == "createUiPage") {
		document.body.replaceChild(createTopButtons(data.content),
					   document.getElementById("myDiv1"));
		document.body.replaceChild(createUiPage(data.content),
					   document.getElementById("myDiv2"));
	    }
	}
	if(data.type === "T_UINEWDOCUMENTWINDOWREQUEST") {
	    displayMessage(data.message);
	    var data = JSON.parse(Aes.Ctr.decrypt(data.data, sessionKey, 128));
	    if(data.type == "showHtmlPage") {
		var wnd = window.document.open("about:blank", "", "scrollbars=yes");
		wnd.document.write(data.content);
		wnd.document.close();
	    }
	}
	if(data.type === "T_GENERICUIREQUEST") {
	    //
	}
    } else {
	// if we get a failure then restart over
	// postData("/api/start", {});
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
    cell.colSpan = frame.header[0].length + 2;
    cell.innerHTML = "<b>" + frame.title + "</b>";
    frame.header.forEach(function(h) {
	var newHeaderItem = createTableItem(id, 0, inputData, h);
	id = newHeaderItem.id;
	tableHeader.appendChild(newHeaderItem.tableRow);
    });
    var count = 0;
    if(frame.rowNumbers) { count = 1; }
    frame.items.forEach(function(i) {
	var newTableItem = createTableItem(id, count, inputData, i);
	id = newTableItem.id;
	tableBody.appendChild(newTableItem.tableRow);
	if(frame.rowNumbers) { count++; }
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
    cell.colSpan = frame.header[0].length + 2;
    cell.innerHTML = "<b>" + frame.title + "</b>";
    frame.header.forEach(function(h) {
	var newHeaderItem = createTableItem(id, 0, inputData, h);
	id = newHeaderItem.id;
	tableHeader.appendChild(newHeaderItem.tableRow);
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

    if(inputData.topButtonList !== undefined) {
	inputData.topButtonList.forEach(function(b) {
//	    var cell = document.createElement('td');
	    var button = document.createElement('button');
	    button.appendChild(document.createTextNode(b.text));
	    button.id = b.id;
	    if(b.callbackUrl != undefined) {
		button.onclick = function() {
		    postEncrypted(b.callbackUrl, inputData);
		    return false;
		};
	    }
	    if(b.callbackFunction != undefined) {
		button.onclick = Function(b.callbackFunction);
	    }
//	    cell.appendChild(button);
	    tableRow.appendChild(button);
	});
    }
    table.appendChild(tableBody);
    table.id = "myDiv1";

    return table;
}

function createAcceptButtons(inputData) {
    var table = document.createElement('table');
    var tableBody = document.createElement('tbody');
    var tableRow = tableBody.insertRow();

    inputData.buttonList.forEach(function(b) {
	var cell = document.createElement('td');
	var button = document.createElement('button');
	button.appendChild(document.createTextNode(b.text));
	button.id = b.id;
	if(b.callbackUrl != undefined) {
	    button.onclick = function() {
		var freshData = { user: inputData.user,
				  priviliges: inputData.priviliges,
				  items: refreshInputDataItems(inputData, false),
				  buttonList: inputData.buttonList };
		postEncrypted(b.callbackUrl, freshData);
		return false;
	    };
	}
	if(b.callbackFunction != undefined) {
	    button.onclick = Function(b.callbackFunction);
	}
	cell.appendChild(button);
	tableRow.appendChild(cell);
    });
    table.appendChild(tableBody);
    return table;
}

function createTableItem(id, count, inputData, item) {
    var tableRow = document.createElement('tr');
    var cell = document.createElement('td');

    if(count != 0) {
	cell.appendChild(document.createTextNode(count));
	tableRow.appendChild(cell);
    }
    item.forEach(function(c) {
	var cell = document.createElement('td');
	if(c[0].itemType === "htmlcell") {
	    cell.innerHTML = c[0].value;
	    cell.style.backgroundColor = c[0].backgroundColor;
	    if(c[0].hidden) { cell.style.visibility = "hidden"; }
	    cell.onclick = Function( c[0].onClickFunction );
	    cell.id = id++;
	    cell.itemType = "htmlcell"
	} else {
	    var newTypedObject = createTypedObject(id, c, inputData);
	    id = newTypedObject.id;
	    cell.appendChild(newTypedObject.item);
	}
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
	if(c[0].itemType === "htmlcell") {
	    cell.innerHTML = c[0].value;
	    cell.style.backgroundColor = c[0].backgroundColor;
	    cell.onclick = Function( c[0].onClickFunction );
	    cell.id = id++;
	    cell.itemType = "htmlcell"
	} else {
	    var newTypedObject = createTypedObject(id, c, inputData);
	    id = newTypedObject.id;
	    cell.appendChild(newTypedObject.item);
	}
	tableRow.appendChild(cell);
    });
    var lastCell = document.createElement('td');
    if(lastRow) {
	var addButton = document.createElement("button");
	addButton.appendChild(document.createTextNode("Create"));
	addButton.id = count;
	addButton.frameId = frameId;
	addButton.onclick = function() { createNewItemToList(inputData, this); }
	lastCell.appendChild(addButton);
    } else {
	var deleteButton = document.createElement("button");
	deleteButton.appendChild(document.createTextNode("Delete"));
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
	    newItem.onclick = Function(i.onClickFunction);
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
	    if(i.hidden) { newItem.style.visibility = "hidden"; }
	    else { newItem.style.visibility = "visible"; }
	    if(i.zeroOption) {
		literalList.push(zeroOption);
		newItem.add(myOption);
	    }
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
	    newItem.onchange = Function(i.onSelectFunction);
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
	    var button = document.createElement('button');
	    if(!i.active) {
		button.disabled = true;
	    }
	    if(i.callbackUrl != undefined) {
		newItem.callbackUrl = i.callbackUrl;
		button.onclick = function() {
		    postEncrypted(i.callbackUrl, { buttonId: i.itemId,
						   buttonData: i.data,
						   items: refreshInputDataItems(inputData,
										false) });
		    return false;
		};
	    }
	    if(i.callbackFunction != undefined) {
		button.onclick = Function(i.callbackFunction);
	    }
	    button.appendChild(document.createTextNode(i.text));
	    newItem.appendChild(button);
	    newItemContainer.appendChild(newItem);
	}

	if(i.itemType === "input") {
	    var newItem = document.createElement('input');
	    newItem.itemType = "input";
	    newItem.key = i.key;
	    newItem.size = i.length;
	    if(i.password === false) {
		newItem.type = "text";
		newItem.value = i.value;
	    } else {
		newItem.type = "password";
	    }
	    if(i.disabled === true) {
		newItem.disabled = true;
	    } else {
		newItem.disabled = false;
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
			     active: i.active,
			     onClickFunction: i.onClickFunction } );
	}
	if(i.itemType === "selection") {
	    var newSelector = { itemType: "selection",
				key: i.key,
				selected: getSelectedItemInList(uiItem),
				active: i.active,
				hidden: i.hidden,
				zeroOption: i.zeroOption,
				onSelectFunction: i.onSelectFunction };
	    if(fullData) { newSelector.list = i.list; }
	    itemList.push(newSelector);
	}
	if(i.itemType === "button") {
	    itemList.push( { itemType: "button",
			     text: i.text,
			     itemId: i.itemId,
			     data: i.data,
			     callbackUrl: i.callbackUrl,
			     active: i.active } );
	}
	if(i.itemType === "input") {
	    itemList.push( { itemType: "input",
			     key: i.key,
			     length: i.length,
			     value: uiItem.value,
			     password: i.password,
			     disabled: i.disabled } );
	}
	if(i.itemType === "htmlcell") {
	    itemList.push( { itemType: "htmlcell",
			     key: i.key,
			     value: i.value } );
	}
    });

    return itemList;
}

