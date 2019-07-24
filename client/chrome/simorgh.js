/**
* How it works:
*   when User tries to visit a URL, we will send the URL to the server
*   and make sure that the URL is safe. Server application check the sanity
*   of the URL using Classification methods tuned for persian banking system.
*   1 - WE DO NOT SEND ANY COOKIE OR USER PERSONAL INFORMATION.
*   2 - THE ONLY INFORMATION WE SEND TO THE SERVER IS URL ITSELF FOR FURTHER ANALYSIS.
*   3 - AFTER ANALYZING THE URL, WE ONLY SAVE MALICIOUS URLS.
*/
(function(){
if (window.simorgh_already_in_page){
    return;
}
window.simorgh_already_in_page = true;

function checkurl(){
    var data = {};
    data['url'] = document.URL;
    data['title'] = document.title;
    data['text'] = $("html").html();
    data['hostname'] = window.location.hostname;
    /* Do not send extra data to keep User's privacy */
    /*data.useragent = window.navigator.userAgent;*/
    /*var d = new Date($.now())*/
    /*data.date = d.toISOString()*/

    var sending = chrome.runtime.sendMessage(
        {data: data},function(response){
            return;
        }
    );
}

function receive_server(request,sender,sendResponse){
    if (request.success == true){
        if (typeof request.is_malicious !== 'undefined'){
            if (request.is_malicious == true){
                $('body').children().css('display','none')
                iframe = $("<iframe>")
                iframe.css("height","100%")
                iframe.css("width","100%")
                iframe.css("border","0px solid black")
                iframe.css("position","absolute")
                iframe.css("top","0px")
                iframe.css("bottom","0px")
                iframe.attr("src",chrome.extension.getURL("extui/block.html"))
                $('body').append(iframe)
            }
        } 
    }else{
        console.log("no succcess from server")
    }
}
/*compatible date function for IE<9*/
if (!Date.prototype.toISOString) {
  (function() {

    function pad(number) {
      if (number < 10) {
        return '0' + number;
      }
      return number;
    }
    Date.prototype.toISOString = function() {
      return this.getUTCFullYear() +
        '-' + pad(this.getUTCMonth() + 1) +
        '-' + pad(this.getUTCDate()) +
        'T' + pad(this.getUTCHours()) +
        ':' + pad(this.getUTCMinutes()) +
        ':' + pad(this.getUTCSeconds()) +
        '.' + (this.getUTCMilliseconds() / 1000).toFixed(3).slice(2, 5) +
        'Z';
    };

  }());
}
chrome.runtime.onMessage.addListener(receive_server);
checkurl();
})();
