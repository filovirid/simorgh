/*
 *some utility function to make the plugin more robust.
 * */

/*check if browser is edge*/
function isedge(){
    var isEdge = !isIE && !!window.StyleMedia;
    return isEdge;
}
/*check if the browser is ie*/
function isie(){
    var isIE = /*@cc_on!@*/false || !!document.documentMode;
    return isIE;
}
/*check if browser is firefox*/
function isfirefox(){
    var isFirefox = typeof InstallTrigger !== 'undefined';
    return isFirefox;
}
/*check if browser is chrome*/
function ischrome(){
    var isChrome = !!window.chrome && (!!window.chrome.webstore || !!window.chrome.runtime);
    return isChrome;
}
/*check if browser is safari*/
function issafari(){
    var isSafari = /constructor/i.test(window.HTMLElement) || (function (p) { return p.toString() === "[object SafariRemoteNotification]"; })(!window['safari'] || (typeof safari !== 'undefined' && safari.pushNotification));
    return isSafari;
}
/*check if browser is firefox and device is android*/
function isandroidff(){
    var ua = navigator.userAgent.toLowerCase();
    var isAndroid = ua.indexOf("android") > -1;
    return (isAndroid && isfirefox());
}
/*check if browser is safari and device is ios*/
function isiphonesafari(){
    var iOS = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
    return (iOS && isiphonesafari())
}
/*check if browser is chrome and device is android*/
function isandroidchrome(){
    var ua = navigator.userAgent.toLowerCase();
    var isAndroid = ua.indexOf("android") > -1;
    return (isAndroid && ischrome());
}

/*send json data to specific url in ajax form*/
function send_data(url,data,success = function(){},error = function(){}){
    if (typeof data !== 'string'){
        data = JSON.stringify(data);
    }
    $.ajax({
        url: url,
        method: "POST",
        dataType: "json",
        data:{data:data}
    }).done(success()).fail(error());
}


