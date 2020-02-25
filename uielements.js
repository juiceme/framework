var framework = require('./framework.js');

function createUiTextNode(key, text) {
    return { itemType: "textnode", key: key, text: text };
}

function createUiTextArea(key, value, cols, rows) {
    if(cols === undefined) { cols = 10; }
    if(rows === undefined) { rows = 1; }
    return { itemType: "textarea", key: key, value: value, cols: cols, rows: rows };
}

function createUiCheckBox(key, checked, title, active, onClickFunction) {
    if(title === undefined) { title = ""; }
    if(active === undefined) { active = true; }
    if(onClickFunction === undefined) { onClickFunction = "return;" }
    return { itemType: "checkbox", key: key, checked: checked, title: title, active: active,
	     onClickFunction: onClickFunction };
}

function createUiSelectionList(key, list, selected, active, hidden, zeroOption, onSelectFunction) {
    var listItems = list.map(function(i) {
	return { text: i, item: i }
    }).filter(function(f) { return f; });
    if(active === undefined) { active = true; }
    if(hidden === undefined) { hidden = false; }
    if(zeroOption === undefined) { zeroOption = true; }
    if(onSelectFunction === undefined) { onSelectFunction = "return;" }
    return { itemType: "selection", key: key, list: listItems, selected: selected, active: active,
	     hidden: hidden, zeroOption: zeroOption, onSelectFunction: onSelectFunction };
}

function createUiMessageButton(text, callbackUrl, data, active) {
    if(active === undefined) { active = true; }
    return { itemType: "button", text: text, callbackUrl: callbackUrl, data: data,
	     active: active };
}

function createUiFunctionButton(text, callbackFunction, active) {
    if(active === undefined) { active = true; }
    return { itemType: "button", text: text, callbackFunction: callbackFunction, active: active };
}

function createUiInputField(key, value, length, password, disabled) {
    if(length === undefined) { length = 15; }
    if(password === undefined) { password = false; }
    if(disabled === undefined) { disabled = false; }
    return { itemType: "input", key: key, value: value, length: length, password: password,
	     disabled: disabled };
}

function createUiHtmlCell(key, value, backgroundColor, hidden, onClickFunction) {
    if(backgroundColor === undefined) { backgroundColor = "#ffffff"; }
    if(hidden  === undefined) { hidden = false; }
    if(onClickFunction === undefined) { onClickFunction = "return;" }
    return { itemType: "htmlcell", key: key, value: value, backgroundColor: backgroundColor, hidden: hidden,
	     onClickFunction: onClickFunction };
}

function createTopButtons(session, additionalButtonList, adminRequest) {
    if(adminRequest === undefined) { adminRequest = false; }
    if(additionalButtonList === undefined) { additionalButtonList = []; }
    var id = 101;
    var topButtonList = [ { id: id++,
			    text: "Log Out",
			    callbackFunction: "postEncrypted('/api/logout', {}); return false;" } ];
    framework.runCallbackByName("createTopButtonList").forEach(function(b) {
	var flag = false; 
	b.priviliges.forEach(function(p) {
	    if(framework.userHasPrivilige(p, framework.getUserByUsername(session.username))) { flag = true; }
	});
	if(flag) {
	    b.button.id = id++;
	    topButtonList.push(b.button);
	}
    });
    // additional buttons need not have defined priviliges
    additionalButtonList.forEach(function(b) {
	b.button.id = id++;
	topButtonList.push(b.button);
    });
    if(framework.userHasPrivilige("system-admin", framework.getUserByUsername(session.username))) {
	if(adminRequest) {
	    topButtonList.push( { id: id++,
				  text: "User Mode",
				  callbackFunction: "postEncrypted('/api/window/0', {}); return false;" } );
	} else {
	    topButtonList.push( { id: id++,
				  text: "Admin Mode",
				  callbackFunction: "postEncrypted('/api/adminpanel', {}); return false;" } );
	}
    } else {
	topButtonList.push( { id: id++,
			      text: getLanguageText(session, "BUTTON_ACCOUNTMODIFY"),
			      callbackFunction: "postEncrypted('/api/useraccountpanel', {}); return false;" } );
    }
    return topButtonList;
}


// Language assist functions

function getLanguageText(session, tag) {
    if(session === null) {
	var language = framework.runCallbackByName("datastorageRead", "main").main.defaultLanguage;
    } else {
	if(session.username !== undefined) {
	    var language = framework.getUserByUsername(session.username).language;
	} else {
	    var language = framework.runCallbackByName("datastorageRead", "main").main.defaultLanguage;
	}
    }
    var langData = framework.runCallbackByName("datastorageRead" ,"language");
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
