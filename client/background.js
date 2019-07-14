/*
* This module is responsible for sending URLs to the 
* server for further process.
*/
var server_url = "http://localhost:8080/catch_data";

function sendserver(request, sender, sendResponse) {
    var d = request.data;
    console.log('send server');
    send_data(server_url,d);
    sendResponse({response: "Response from background script"});
}

browser.runtime.onMessage.addListener(sendserver);

