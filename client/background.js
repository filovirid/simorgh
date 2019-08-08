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
    console.log("we are in malicious")
    if (is_valid_bank_domain(data.hostname)){return false;}
    console.log("here")
    var txt = data.text;
    if (txt == ""){ return false;}

    console.log("here1")
    if(domain_in_exclusion_list(data.hostname)){return false;}

    console.log("here2")
    var ssdeep_score = get_ssdeep_score(txt)
    var mal_score = ssdeep_score.mal;
    var ben_score = ssdeep_score.ben;
    var sk = has_saman_keywords(txt);
    var pk = has_parsian_keywords(txt);
    var has_bnk_in_content = is_find_valid_bank_domain_in_content(txt);
    // get title feature
    var title = data.title;
    var has_title_keyword = has_special_title_keyword(title);
    if (sk > 0.75 || pk > 0.75){
        return true;
    }
    if (ben_score > 0 || mal_score >0) { 
        return true;
    }
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
        'behpardakht.com','pep.co.ir','sepehrpay.com',
        'sep.ir','pna.co.ir','pec.ir',
        'sadadpsp.ir','fanavacard.ir',
        'irankish.com','mca.co.ir','mcac.co.ir',
        'payping.ir','sayancard.ir','zarinpal.com'
    ]
}

function is_valid_bank_domain(url){
    var valid_bank_list = get_bank_list();
    var tldparser = psl.parse(url);
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

function domain_in_exclusion_list(domain_name){
    console.log("in exclusion_list check")
    var ex_list = get_exclusion_list()
    console.log("ex list is")
    console.log(ex_list)
    var tldparser = psl.parse(domain_name)
    console.log("our domain is")
    console.log(tldparser.domain)
    if (tldparser.domain == ""){
        return false;
    }
    if (ex_list.indexOf(tldparser.domain) > -1){
        return true;
    }
    return false;
}

function get_exclusion_list(){
    // if the domain name is one of the famous search engine list
    // or other domain name in exclusion list, don't blacklist it.
    // this exclusion list manually updated from exclusion.list file.
    return [
        'president.ir','saamad.ir','dolat.ir','ejraee.gov.ir',
        'cabinet.gov.ir','lvp.ir','dotic.ir','women.gov.ir',
        'ghanoonasasi.ir','freezones.ir','ias.ac.ir','persianacademy.ir',
        'honar.ac.ir','ams.ac.ir','dchq.ir','epe.ir',
        'css.ir','nicc.ir','omoremajles.ir','cila.ir',
        'mporg.ir','imps.ac.ir','nipo.gov.ir','amar.org.ir',
        'sci.org.ir','srtc.ac.ir','ncc.org.ir','gtc.ac.ir',
        'isti.ir','bmn.ir','insf.org','isaar.ir',
        'navideshahed.com','zakhireh.co.ir','isaarcsi.ir','chemical-victims.com',
        'rcs.ir','raro.ir','mpo-helal.org','aeoi.org.ir',
        'doe.ir','ichto.ir','richt.ir','tichct.org',
        'eachto.org','ilamchto.ir','miraschb.ir','golestanchto.ir',
        'urmiachto.ir','isfahancht.ir','razavi-chto.ir','qchto.ir',
        'miras-ar.ir','skchto.com','chht-sb.ir','mchto.ir',
        'yazdcity.ir','tchto-portal.ir','nkchto.ir','mirassemnan.ir',
        'kr.ir','gilanchto.ir','nlai.ir','hadafmandi.ir',
        'ict.gov.ir','scict.ir','post.ir','cra.ir',
        'postbank.ir','ito.gov.ir','tic.ir','payamaviation.ir',
        'ictfaculty.ir','itrc.ac.ir','isa.ir','isrc.ac.ir',
        'medu.ir','sce.ir','srttu.edu','oerp.ir',
        'rie.ir','cfu.ac.ir','kanoonparvaresh.com','dres.ir',
        'lmoiran.ir','teo.ir','vaja.ir','mefa.gov.ir',
        'investiniran.ir','intamedia.ir','irica.gov.ir','ipo.ir',
        'seo.ir','tamliki.ir','audit.org.ir','ific.org.ir',
        'spoi.ir','mfa.gov.ir','sir.ac.ir','behdasht.gov.ir',
        'salamat.gov.ir','sanjeshp.ir','fda.gov.ir','irimc.org',
        'hbi.ir','pasteur.ac.ir','ibto.ir','ibrf.ir',
        'srd.ir','mcls.gov.ir','mashaghelkhanegi.ir','bazar-eshteghal.ir',
        'irantvto.ir','tamin.ir','behzisti.ir','ihio.gov.ir',
        'ttbank.ir','lssi.ir','roostaa.ir','cspfiran.com',
        'cigf.ir','maj.ir','areo.ir','ivo.ir',
        'frw.org.ir','ashayer.ir','ppo.ir','shilat.com',
        'laoi.ir','corc.ir','agriservices.ir','sfida.ir',
        'apcp.ir','itvhe.ac.ir','iranslal.com','agri-peri.ir',
        'justice.ir','tazirat.gov.ir','mod.gov.ir','iranhavafaza.com',
        'tridi.ir','mut.ac.ir','esata.ir','fatehnet.net',
        'esdo.ir','btn.ir','mrud.ir','weather.ir',
        'cao.ir','rai.ir','cdtic.ir','udrc.ir',
        'rmto.ir','pmo.ir','bonyadmaskan.com','nlho.ir',
        'cobi.gov.ir','ntoir.gov.ir','bhrc.ac.ir','uarc.org.ir',
        'tsml.ir','iranair.com','airport.ir','mimt.gov.ir',
        'isiri.org','gsi.ir','isipo.ir','imidro.gov.ir',
        'idro.ir','bim.ir','sif-gov.ir','gtc-portal.com',
        'cppo.ir','ecommerce.gov.ir','tpo.ir','egfi.org',
        'irisl.net','iranfair.com','irancode.ir','incc.ir',
        'itsr.ir','irtobacco.com','imi.ir','msc.ir',
        'impasco.com','nicico.com','esfahansteel.com','ksc.ir',
        'niscoir.com','pgsez.ir','msrt.ir','nrisp.ac.ir',
        'iecf.ir','samt.ac.ir','sanjesh.org','irost.org',
        'saorg.ir','stpia.ir','swf.ir','isc.gov.ir',
        'atf.gov.ir','cissc.ir','mjazb.ir','iiees.ac.ir',
        'irphe.ac.ir','farhang.gov.ir','ricac.ac.ir','irna.ir',
        'hajnews.ir','oghaf.ir','icro.ir','samandehi.ir',
        'iranpl.ir','moi.ir','sabteahval.ir','imo.org.ir',
        'ndmo.ir','police.ir','golestanp.ir','portal-il.ir',
        'nkhorasan.ir','ostb.ir','ostan-qom.ir','sko.ir',
        'ostandari-zn.ir','ostan-sm.ir','qazvin.gov.ir','farsp.ir',
        'ostan-yz.ir','ostan-hm.ir','hormozgan.ir','ostan-mr.ir',
        'ostan-mz.ir','ostan-lr.ir','ostan-kb.ir','ostan-kd.ir',
        'sb-ostan.ir','ostan-kz.ir','khorasan.ir','ostan-cb.ir',
        'ostan-th.ir','ostan-ar.ir','ostan-ag.gov.ir','gilan.ir',
        'ostan-as.gov.ir','mop.ir','niordc.ir','nigc.ir',
        'nipc.ir','put.ac.ir','nioc.ir','iies.org',
        'moe.gov.ir','tavanir.org.ir','wrm.ir','nww.ir',
        'tpph.ir','igmc.ir','nri.ac.ir','suna.org.ir',
        'saba.org.ir','ipdc.ir','wri.ac.ir','msy.gov.ir',
        'tanavar.ir','ghahremanan.ir','olympic.ir','paralympic.ir',
        'bornanews.ir','cbi.ir','bmi.ir','bank-maskan.ir',
        'banksepah.ir','bki.ir','edbi.ir','enbank.ir',
        'parsian-bank.ir','bpi.ir','karafarinbank.ir','sb24.com',
        'sinabank.ir','sbank.ir','shahr-bank.ir','bank-day.ir',
        'bsi.ir','bankmellat.ir','tejaratbank.ir','rb24.ir',
        'hibank24.ir','tourismbank.ir','izbank.ir','ghbi.ir',
        'ansarbank.com','middleeastbank.ir','ivbb.ir','ba24.ir',
        'cid.ir','kosarfci.ir','askariye.ir','caspianci.ir',
        'qmb.ir','rqbank.ir','centinsur.ir','iraninsurance.ir',
        'bimehasia.com','alborzinsurance.ir','dana-insurance.com','mic.co.ir',
        'parsianinsurance.ir','karafarin-insurance.ir','sinainsurance.com','tins.ir',
        'razi24.ir','samaninsurance.ir','dayins.com','melat.ir',
        'novininsurance.com','pasargadinsurance.ir','bimehmihan.ir','kowsarinsurance.ir',
        'bimehma.ir','bimehtaavon.com','sarmadins.ir','hafezinsurance.ir',
        'omid-insurance.ir','asmari-insurance.com','abfacs.ir','dadgostari-kh.ir',
        'dadgostari-yz.ir','dadgostari-mz.ir','dadgostari-bs.ir','dadgostari-es.ir',
        'dadgostari-th.ir','dadgostari-gl.ir','dadgostari-as.ir','dadgostari-ag.ir',
        'dadgostari-al.ir','dadgostari-fr.ir','dadgostari-hm.ir','dadgostari-gs.ir',
        'dadgostari-mr.ir','dadgostari-hr.ir','dadgostari-kr.ir','dadgostari-cb.ir',
        'dadgostari-il.ir','dadgostari-qm.ir','dadgostari-kl.ir','dadgostari-lr.ir',
        'dadgostari-khz.ir','dadgostari-sm.ir','parliran.ir','icana.ir',
        'ical.ir','cmir.ir','shora-gc.ir','2noor.com',
        '313fadai.ir','absharatefeha.ir','aghigh.ir','ahaad.ir',
        'ahlebeit.tk','ahlolbait.com','ahlulbaytclub.com','ahsanolhadis.ir',
        'ajashohada.ir','alghadir.ir','alkazem.ir','almiqat.com',
        'andisheqom.com','anhar.ir','anti666.ir','anvartaha.ir',
        'askdin.com','asr-entezar.ir','ayehayeentezar.com','kowsarblog.ir',
        'bahmanemamzadegan.ir','behdashtemanavi.com','besh.ir','bigharar.ir',
        'binesheno.com','bonyadedoa.com','bonyadhad.ir','darolshieh.net',
        'dinonline.com','ebnearabi.com','bidari-andishe.ir','gomnam.ir',
        'hadana.ir','hadith.net','hadithlib.com','hagh-olhaghigh.com',
        'hajj.ir','hayauni.ir','i20.ir','iska.ir',
        'islamicdatabank.com','isoa.ir','jannatefakkeh.com','jelveh.org',
        'kalamehaq.ir','karbobala.com','ketabequran.ir','tebyan.net',
        'khatteemam.ir','khayyen.ir','kheimegah.com','maarefislam.net',
        'maarefquran.com','mahdaviat.org','etudfrance.com','mahdieha.ir',
        'mahdiehtehran.tv','maktabozahra.ir','masaf.ir','masajed.net',
        'masjedbelal.ir','masjednet.ir','mataf.ir','mehad.org',
        'meza.ir','moazen-haram.ir','moheban-hfze.ir','monji12.com',
        'ghasam.ir','motaghin.com','mouood.org','salehin.ir',
        'muhammadi.org','naseroon.ir','dde.ir','nooremobin.org',
        'parsquran.com','pasokhgoo.ir','porseman.org','qaraati.ir',
        'qunoot.net','quranfa.ir','quranhefz.ir','quraniran.ir',
        'quran-mojam.ir','quranmp3.ir','raad-alghadir.org','rahpouyan.com',
        'rahyafte.com','ramezan.com','ravayatgar.org','aqr.ir',
        'basij.ir','sadaadnoor.ir','safiresobh.com','sahebzaman.org',
        'salate-jomeh.ir','salavaat.com','salehintehran.ir','samenquran.ir',
        'sayedalkarim.ir','sedayeshia.com','shahecheragh.ir','shahed41.ir',
        'shia24.com','shia-leaders.com','shiastudies.net','sibtayn.com',
        'soroushhekmat.ir','tafahoseshohada.ir','tahaquran.ir','tamhid.ir',
        'tanghim.com','mrdollar.biz','tanzil.net','tavabin.ir',
        'tebyan12.net','telavat.com','t-pasokhgoo.ir','blogfa.com',
        'yamojir.com','zamane.info','zeynabkf.ir','zohd.ir',
        '780.ir','parsonline.com','digikala.com','shaparak.ir',
        'irib.ir','zarinpal.com','enamad.ir','rightel.ir',
        'mci.ir','niniban.com','tehran.ir','irancell.ir',
        'e-estekhdam.com','nic.ir','emalls.ir','esam.ir',
        'netbarg.com','iranecar.com','cinematicket.org','ssaa.ir',
        'rahvar120.ir','khamenei.ir','eranico.com','alibaba.ir',
        'tax.gov.ir','zoodfood.com','niazerooz.com','modiseh.com',
        'roham.ws','chmail.ir','lastsecond.ir','bayanbox.ir',
        'adliran.ir','mihanstore.net','zanbil.ir','irimo.ir',
        'mobinnet.ir','hostiran.net','kimiaonline.com','manofile.com',
        'mofidonline.com','ikco.ir','tct.ir','alodoctor.ir',
        'sahamyab.com','sabanet.ir','asiatech.ir','hiweb.ir',
        '1544.ir','time.ir','shatel.ir','mci24.com',
        'mdc.ir','1000charge.com','asibdidegan.com','ayneshamdoon.ir',
        'behnamcharity.org.ir','bntabriz.ir','bootorab.com','chargeok.com',
        'charjer.ir','chbehzisty.ir','ch-iran.org','dastavardha.com',
        'ebratmuseum.ir','samanepay.com','echargeu.ir','ehda.center',
        'sbmu.ac.ir','ekramtehran.ir','emdad.ir','engbasijsem.ir',
        'eyn.ir','fordo.ir','getsharj.com','ghadiany.com',
        'haj.ir','hamrahsharj.ir','i24.ir','ibso.ir',
        'ir93.com','javananhelal.ir','kashan-behzisti.ir','mahak-charity.org',
        'mah-as.com','afsaran.ir','mehranehcharity.ir','mehrhouse.com',
        'menhajeferdowsian.ir','nikancharity.org','pchamran.ir','pmbhva.ir',
        'raad-charity.org','persianblog.ir','rissp.org','samarcharity.com',
        'serajnet.org','shiraznarjes.com','simcart.com','beest.ir',
        'tellmeaboutiran.com','bellff.ir','karait.com','nikzee.com',
        'dbuy.ir','dcanon.ir','deytodey.ir','digibaneh.com',
        'digikhane.com','digikharid.com','digimana.ir','datakey.ir',
        'chilazemdari.com','cnstore.ir','chare.ir','bziran.com',
        'boorsika.com','bizonline.ir','digisystemyazd.com','digionline.ir',
        'digibag.net','bitdefenderme.ir','itbazar.com','digitalbaran.com',
        'donya-digital.com','ebagh.com','ebazar.biz','ebpnovin.com',
        'ecartridge.ir','efoo.ir','egkala.ir','ejanebi.com',
        'ekalamarket.com','elebazar.ir','emertad.com','eshopp.ir',
        'etoranj.com','exif.ir','fafait.net','fanasan.com',
        'farhangeaval.ir','fayab.com','feresto.com','final.ir',
        'freeze.ir','ghalebazi.com','globyte.ir','goldtag.net',
        'gooshishop.com','gsm-server.ir','hamrahebartar.com','hediyebazar.com',
        'hmobile.ir','holooshop.ir','hpaba.com','hypercafe.ir',
        'hypershine.ir','ighab.com','ikaspersky.com','ilyasystem.com',
        'internetbazar.ir','iprotect.ir','iranlaptopparts.com','iranshahrshop.com',
        'ireshops.ir','ir-shop.ir','jahangostarpars.com','janebi.com',
        'jensekhoob.com','jetkharid.com','kajalmarket.com','kalabiz.ir',
        'kala-center.ir','kalaina.com','mahashop.ir','mahfashop.com',
        'marketestan.com','merqc.com','romis.com','sabzcenter.com',
        'sadetar.com','saymandigital.com','soghatenab.com','startkala.com',
        'storeiranian.com','sunkala.store','tablet.ir','tadabbor.org',
        'tadkala.com','comland.ir','lioncomputer.ir','mtplus.mobi',
        'tabnak.ir','mehrnews.com','khabaronline.ir','shahrekhabar.com',
        'yjc.ir','farsnews.com','asriran.com','isna.ir',
        'mashreghnews.ir','jamnews.ir','fararu.com','fardanews.com',
        'alef.ir','iranjib.ir','tnews.ir','dana.ir',
        'jamejamonline.ir','parsine.com','seratnews.ir','khabarpu.com',
        'vananews.ir','mizanonline.ir','hamshahrionline.ir','aftabnews.ir',
        'bamdad.net','shomanews.com','rajanews.com','donya-e-eqtesad.com',
        'rokna.ir','faradeed.ir','roozno.com','ilna.ir',
        'snn.ir','tabnakbato.ir','iribnews.ir','parstoday.com',
        'eghtesadonline.com','saat24.com','bultannews.com','entekhab.ir',
        'ammarname.ir','basijpress.ir','bfnews.ir','defapress.ir',
        'ehavadar.com','rouhollah.ir','fatehan.ir','harammotahar.ir',
        'iqna.ir','irdc.ir','koolebar.ir','labbaik.ir',
        'leader.ir','madayeh.com','ommatnews.ir','shahidblog.com',
        'tanvir.ir','teror-victims.com','valiamr.com','ebanksepah.ir',
        'enbank.net','mebank.ir','refah-bank.ir','cinoor.ir',
        'varzesh3.com','picofile.com','zoomit.ir','zoomg.ir',
        '90tv.ir','gsm.ir','1varzesh.com','hamyarwp.com',
        'abadis.ir','meghdadit.com','itpro.ir','rtl-theme.com',
        'bigtheme.ir','gadgetnews.ir','parsfootball.com','shopkeeper.ir',
        'marketwp.ir','gooyait.com','digibyte.ir','digizar.ir',
        'donyacomputer.com','ever247.net','galleriha.com','ghanongostar.com',
        'iranhp.ir','mob.ir','mobilekomak.com','motamem.org',
        'thevaluefestival.ir','farsicom.com','farsicomcrm.com','sarveno.com',
        'sarvcrm.com','pars-cup.com','namnak.com','persianv.com',
        'facenama.com','cloob.com','tarafdari.com','irannaz.com',
        'digiato.com','rasekhoon.net','aviny.com','wisgoon.com',
        'parsnaz.ir','caspiangc.ir','hojb.ir','okhowah.com',
        'shahid-jafari.ir','shds.ir','namasha.com','telewebion.com',
        'aparat.com','musiceiranian.ir','mibinim.com','filmnet.ir',
        'lenz.ir','tva.tv','iseema.ir','kanape.ir',
        'plaan.ir','afarinak.ir','appido.ir','vidanama.com',
        'Namava.ir','aionet.ir','uast.ac.ir','ut.ac.ir',
        'kanoon.ir','tvu.ac.ir','pnu.ac.ir','um.ac.ir',
        'hawzah.net','roshd.ir','aut.ac.ir','iauctb.ac.ir',
        'portaltvto.com','irandoc.ac.ir','srbiau.ac.ir','bdv.ir',
        'mazums.ac.ir','lordpopup.com','divar.ir','bama.ir',
        'sheypoor.com','popkade.ir','irpopup.ir','anetwork.ir',
        'sabavision.com','rahnama.com','popupads.ir','nextpopup.ir',
        'yasdl.com','cafebazaar.ir','asandl.com','downloadha.com',
        'vatandownload.com','sarzamindownload.com','parspa.ir','filesell.ir',
        'gilbazar.com','shatelland.com','top2download.com','mihanblog.com',
        'blog.ir','rozblog.com','loxblog.com','parsiblog.com',
        'niniweblog.com','google.com','yahoo.com','bing.com'
    ]
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
