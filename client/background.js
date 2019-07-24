/*
* This module is responsible for sending URLs to the 
* server for further process.
*/
var server_url = "http://simorgh.filovirid.com/url_check";

browser.runtime.onMessage.addListener(sendserver);
function sendserver(request,sender,sendResponse){
    // get the tabid of the sender
    tabid = sender.tab.id
    /*
    * shallow check for phishing attack in client side
    * and send the url to the server for further analysys.
    * to respect user's privacy, just send URL without 
    * html text or title.
    */
    if(is_phishing_client(request.data)){
        browser.tabs.sendMessage(tabid,{success:true,is_malicious:true})
    }
    // also get the result from the server
    const response = $.ajax({
        //contentType: 'application/json;charset=utf-8',
        data:{url:request.data['url']},
        dataType: 'json',
        method: 'POST',
        url: server_url,
    });
    response.done(data => {
        if (typeof data.success !== 'undefined'){
            if (data.success == true){
                browser.tabs.sendMessage(tabid,{success:data.success,is_malicious:data.is_malicious})
            }else{
                browser.tabs.sendMessage(tabid,{success:data.success})
            }
        }
    });
    response.fail(data => {
        return;
    });
}
function is_phishing_client(data){
    return is_malicious(data);
}

function is_malicious(data){
    if (is_valid_bank_domain(data.hostname)){return false;}
    var txt = data.text;
    if (txt == ""){ return false;}
    var ssdeep_score = get_ssdeep_score(txt)
    var mal_score = ssdeep_score.mal;
    var ben_score = ssdeep_score.ben;
    var sk = has_saman_keywords(txt);
    var pk = has_parsian_keywords(txt);
    var has_bnk_in_content = is_find_valid_bank_domain_in_content(txt);
    // get title feature
    var title = data.title;
    var has_title_keyword = has_special_title_keyword(title);
    if (sk > 0.75 || pk > 0.75){return true;}
    if (ben_score > 0 || mal_score >0) { return true;}
    if (has_bnk_in_content || is_in_url_word(data.url)){
        if ((sk>0 || pk>0) && has_title_keyword){
            return true;
        }
    }
    return false;
}

function is_find_valid_bank_domain_in_content(txt){
    var bnk_lst = get_bank_list()
    for (var x in bnk_lst){
        if (txt.search(bnk_lst[x]) != -1){
            return true;
        }
    }
    return false
}
function is_in_url_word(url){
    url = url.toLowerCase()
    var w = ['bank','account','shaparak','amount','payment','peyment','دروازه','پرداخت','الكترونيك','parsian','saman','refah','banc']
    for (var x in w){
        if (url.search(w[x]) != -1){
            return true;
        }
    }
    return false;
}

function has_special_title_keyword(title){
    if (title == ""){return false;}
    var ttl_list = get_special_title_keyword();
    for (var x in ttl_list){
        if (title.search(ttl_list[x]) != -1){
            return true;
        }
    }
}
function get_ssdeep_score(txt,th = 70){
    var mal = 0
    var ben = 0
    var mal_ssdeep = read_malicious_ssdeep()
    var ben_ssdeep = read_benign_ssdeep()
    var h = ssdeep.digest(txt)
    for (var x in ben_ssdeep){
        if (ssdeep.similarity(h,ben_ssdeep[x]) >= th){
            ben += 1
        }
    }
    for (var x in mal_ssdeep){
        if (ssdeep.similarity(h,mal_ssdeep[x]) >= th){
            mal += 1
        }
    }
    return {"mal":mal,"ben":ben}
}



function saman_keywords(){
    return [
        'شماره کارت',
        'رمز اینترنتی',
        'تاریخ انقضا',
        'کد امنیتی',
        'اطلاعات کارت',
        'زمان باقی مانده',
        'انصراف',
        'اصلاح',
        'حذف',
        'پرداخت',
        'سامان',
        'shaparak.ir'
    ]
}
        

function parsian_keywords(){
    return [
        'شماره كارت',
        'رمز اينترنتي',
        'تاريخ انقضا',
        'اطلاعات کارت',
        'پرداخت',
        'انصراف',
        'پارسيان',
        'pecco24.com',
        'pec.ir',
        'سقف مجاز خريد روزانه'
    ]
}

function has_saman_keywords(txt){
    var pk = saman_keywords();
    var found = [];
    for (var x in pk){
        if (txt.search(pk[x]) != -1){
            found.push(pk[x])
        }
    }
    return found.length/pk.length
}
function has_parsian_keywords(txt){
    var pk = parsian_keywords();
    var found = [];
    for (var x in pk){
        if (txt.search(pk[x]) != -1){
            found.push(pk[x]);
        }
    }
    return found.length/pk.length;
}

function get_special_title_keyword(){
    return [
        'دروازه',
        'پرداخت',
        'شرکت',
        'تجارت',
        'الكترونيك',
        'پارسيان',
        'اینترنتی',
        'سامان'
    ]
}


function get_bank_list(){
    return  [
        'shaparak.ir','asanpardakht.ir',
        '733.ir','ecd-co.ir','sayancard.ir',
        'behpardakht.com','pep.co.ir',
        'sep.ir','pna.co.ir','pec.ir',
        'sadadpsp.ir','fanavacard.ir',
        'irankish.com','mca.co.ir',
        'payping.ir','sayancard.ir','zarinpal.com'
    ]
}

function is_valid_bank_domain(url){
    var valid_bank_list = get_bank_list()
    var tldparser = psl.parse(url)
    if (tldparser.domain == ""){
        return false;
    }
    if (valid_bank_list.indexOf(tldparser.domain) > -1){
        return true;
    }
    return false;
}
function read_benign_ssdeep(){
    h = [
        '384:84s9SChgrhSTczCcsScav4r4mWMsYRKvgaizlaEiizo15zHzJ0xdIYf4:0SCOelori4mKizlaEjzG',
        '384:1M2jhk7xwt4/JKmtHY5mKwt40bNzkfGleO890wt6mTe:1WDzZkE',
        '192:hb37AfzcHL44cI3tfNO6nH8y8Bjib2N+2iH/6nCulsEVtCxCuSihiHzZ3:hD8044c0D1nHXmjiSHFnrlsEVtTbHzZ3',
        '192:hb37AfzcHL44cI3tfNO6nH8y8Bjib2N+2iH/6nCulsEVtCxCuSihiHzZ3:hD8044c0D1nHXmjiSHFnrlsEVtTbHzZ3',
        '384:1MeBjhk7xwt4/DKmtHY5mKwt40bNzkfGleO890wt6mJe:1bGNzZkC',
        '384:1Mpjhk7xwt4/MKmtHY5mKwt40bNzkfGleO890wt6m4e:1rozZk/'
    ]
    return h;
}

function read_malicious_ssdeep(){
    h = [
        '384:eH8BZg7FqjY+pQhVGYSHvR6iCYslTa8cjWzBu:jg7Fq8+pQhVGXHvY7YslO8c6zQ',
        '384:8/chbu0aexKrxUXTrfDnDrOqQkrLSkySZrZIWr5OJrwQOskz61+i6J4IwRCTsNOb:8ybtghX33tzyzsP8fkma9YU+/Xe9b4Lj',
        '384:8/chbu0aexKrxUXTrfDnDrOqQkrLSkySZrZIWr5OJrwQOskzWh+i+J4IwRCTsNOo:8ybtghX9ftzt',
        '384:EzA6UnQrWEKE1E1Bo8GKSOWfV8oyzhAjSd8PemKo11Y1zg:EzA6+QrWEKE1E1OLh8qAzg',
        '768:EgEcvmzmLXSdpYNNnMwMQsYO5fUJazhzsP8fkma9YU+/Xe9b4LdIyoU:EgEc+zECggM0zhC8fkmaG/Xe9b4LdJv',
        '768:EgEcvmzmLXSdpYNNnMwMQPYO5fUyazA3sP8fkma9YU+/Xe9b4LdIyoh:EgEc+zECpgMxz+C8fkmaG/Xe9b4LdJ8'
    ]
    return h;
}


//function to calculate ssdeep
(function () {
    var ssdeep = {};
    var isBrowser = false;
    if (typeof module !== 'undefined' && module.exports) {
        exports = module.exports = ssdeep;
    } else {//for browser
        this.ssdeep = ssdeep;
        isBrowser = true;
    }

    var HASH_PRIME = 16777619;
    var HASH_INIT = 671226215;
    var ROLLING_WINDOW = 7;
    var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    function toUTF8Array (str) {
      var out = [], p = 0;
      for (var i = 0; i < str.length; i++) {
        var c = str.charCodeAt(i);
        if (c < 128) {
          out[p++] = c;
        } else if (c < 2048) {
          out[p++] = (c >> 6) | 192;
          out[p++] = (c & 63) | 128;
        } else if (
            ((c & 0xFC00) == 0xD800) && (i + 1) < str.length &&
            ((str.charCodeAt(i + 1) & 0xFC00) == 0xDC00)) {
          // Surrogate Pair
          c = 0x10000 + ((c & 0x03FF) << 10) + (str.charCodeAt(++i) & 0x03FF);
          out[p++] = (c >> 18) | 240;
          out[p++] = ((c >> 12) & 63) | 128;
          out[p++] = ((c >> 6) & 63) | 128;
          out[p++] = (c & 63) | 128;
        } else {
          out[p++] = (c >> 12) | 224;
          out[p++] = ((c >> 6) & 63) | 128;
          out[p++] = (c & 63) | 128;
        }
      }
      return out;
    }

    /*
    * Add integers, wrapping at 2^32. This uses 16-bit operations internally
    * to work around bugs in some JS interpreters.
    */
    function safe_add (x, y) {
      var lsw = (x & 0xFFFF) + (y & 0xFFFF)
      var msw = (x >> 16) + (y >> 16) + (lsw >> 16)
      return (msw << 16) | (lsw & 0xFFFF)
    }

    /*
      1000 0000
      1000 0000
      0000 0001
    */

    function safe_multiply(x, y) {
  		/*
  			a = a00 + a16
  			b = b00 + b16
  			a*b = (a00 + a16)(b00 + b16)
  				= a00b00 + a00b16 + a16b00 + a16b16

  			a16b16 overflows the 32bits
  		 */
     var xlsw = (x & 0xFFFF)
     var xmsw = (x >> 16) +(xlsw >> 16);
     var ylsw = (y & 0xFFFF)
     var ymsw = (y >> 16) +(ylsw >> 16);
  		var a16 = xmsw
  		var a00 = xlsw
  		var b16 = ymsw
  		var b00 = ylsw
  		var c16, c00
  		c00 = a00 * b00
  		c16 = c00 >>> 16

  		c16 += a16 * b00
  		c16 &= 0xFFFF		// Not required but improves performance
  		c16 += a00 * b16

  		xlsw = c00 & 0xFFFF
  		xmsw= c16 & 0xFFFF

  		return (xmsw << 16) | (xlsw & 0xFFFF)
  	}

    /*
    * Bitwise rotate a 32-bit number to the left.
    */
    function bit_rol (num, cnt) {
      return (num << cnt) | (num >>> (32 - cnt))
    }

    function fnv (h, c) {
      return (safe_multiply(h,HASH_PRIME) ^ c)>>>0;
    }

    function levenshtein (str1, str2) {
        // base cases
        if (str1 === str2) return 0;
        if (str1.length === 0) return str2.length;
        if (str2.length === 0) return str1.length;

        // two rows
        var prevRow  = new Array(str2.length + 1),
            curCol, nextCol, i, j, tmp;

        // initialise previous row
        for (i=0; i<prevRow.length; ++i) {
            prevRow[i] = i;
        }

        for (i=0; i<str1.length; ++i) {
            nextCol = i + 1;

            for (j=0; j<str2.length; ++j) {
                curCol = nextCol;

                // substution
                nextCol = prevRow[j] + ( (str1.charAt(i) === str2.charAt(j)) ? 0 : 1 );
                // insertion
                tmp = curCol + 1;
                if (nextCol > tmp) {
                    nextCol = tmp;
                }
                // deletion
                tmp = prevRow[j + 1] + 1;
                if (nextCol > tmp) {
                    nextCol = tmp;
                }

                // copy current col value into previous (in preparation for next iteration)
                prevRow[j] = curCol;
            }

            // copy last col value into previous (in preparation for next iteration)
            prevRow[j] = nextCol;
        }
        return nextCol;
    }

    function RollHash () {
      this.rolling_window = new Array(ROLLING_WINDOW);
      this.h1 =  0
      this.h2 = 0
      this.h3 = 0
      this.n = 0
    }
    RollHash.prototype.update = function (c) {
      this.h2 = safe_add(this.h2, -this.h1);
      var mut = (ROLLING_WINDOW * c);
      this.h2 = safe_add(this.h2, mut) >>>0;
      this.h1 = safe_add(this.h1, c);

      var val = (this.rolling_window[this.n % ROLLING_WINDOW] || 0);
      this.h1 = safe_add(this.h1, -val) >>>0;
      this.rolling_window[this.n % ROLLING_WINDOW] = c;
      this.n++;

      this.h3 = this.h3 << 5;
      this.h3 = (this.h3 ^ c) >>>0;
    };
    RollHash.prototype.sum = function () {
      return (this.h1 + this.h2 + this.h3) >>>0;
    };

    function piecewiseHash (bytes, triggerValue) {
        var signatures = ['','', ''];
        var h1 = HASH_INIT;
        var h2 = HASH_INIT;
        var rh = new RollHash();
        for (var i = 0, len = bytes.length; i < len; i++) {
            var thisByte = bytes[i];

            h1 = fnv(h1, thisByte);
            h2 = fnv(h2, thisByte);

            rh.update(thisByte);

            if (i === (len - 1) || rh.sum() % triggerValue === (triggerValue - 1)) {
                signatures[0] += B64.charAt(h1&63);
                signatures[2] = triggerValue;
                h1 = HASH_INIT;
            }
            if (i === (len - 1) || rh.sum() % (triggerValue * 2) === (triggerValue * 2 - 1) ) {
                signatures[1] += B64.charAt(h2&63);
                signatures[2] = triggerValue;
                h2 = HASH_INIT;
            }
        }
        return signatures;
    }

    function digest (bytes) {
        var minb = 3;
        var bi = Math.ceil(Math.log(bytes.length/(64*minb))/Math.log(2));
        bi = Math.max(3, bi);

        var signatures = piecewiseHash(bytes, minb << bi);
        while (bi>0 && signatures[0].length < 32){
            signatures = piecewiseHash(bytes, minb << --bi);
        }
        return signatures[2] + ':' + signatures[0] + ':' + signatures[1];
    }

    function matchScore (s1, s2) {
        var e = levenshtein(s1, s2);
        var r = 1 - e/Math.max(s1.length ,s2.length);
        return r * 100;
    }

    ssdeep.digest = function (data) {
        if (typeof data === 'string') {
            data = isBrowser?toUTF8Array(data):new Buffer(data).toJSON().data;
        }
        return digest(data);
    };

    ssdeep.similarity = function (d1, d2) {
        var b1 = B64.indexOf(d1.charAt(0));
        var b2 = B64.indexOf(d2.charAt(0));
        if (b1 > b2) return arguments.callee(d2, d1);

        if (Math.abs(b1-b2) > 1) {
            return 0;
        } else if (b1 === b2) {
            return matchScore(d1.split(':')[1], d2.split(':')[1]);
        } else {
            return matchScore(d1.split(':')[2], d2.split(':')[1]);
        }
    };
})();
