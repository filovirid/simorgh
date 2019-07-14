/**
* How it works:
*   when User tries to visit a URL, we will send the URL to the server
*   and make sure that the URL is safe. Server application check the sanity
*   of the URL using Classification methods tuned for persian banking system.
*   1 - WE DO NOT SEND ANY COOKIE OR USER PERSONAL INFORMATION.
*   2 - WE ARE NOT INTERESTED IN QUERY PARAMETERS OF THE URL WHICH SINCE IT MAY CONTAIN 
*   PERSONAL INFORMATION.
*   3 - THE ONLY INFORMATION WE SEND TO THE SERVER IS URL ITSELF FOR FURTHER ANALYSIS.
*/
function checkurl(){
    var data = {};
    data.url = document.URL;
    data.useragent = window.navigator.userAgent;
    var d = new Date($.now())
    data.date = d.toISOString()
    var sending = browser.runtime.sendMessage({
        data: data
    });
    sending.then(func_response,func_error);
}

function func_response(resp){
    return;
}

function func_error(err){
    return;
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
checkurl();
