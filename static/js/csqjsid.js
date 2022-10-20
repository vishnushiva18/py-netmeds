include("https://cdn.rawgit.com/neocotic/qrious/master/dist/qrious.min.js")

// appBaseURL = "http://localhost:5002"
appBaseURL = "https://jsign.livetrack.in";
qrElementID = null;
function JSIDShowQR(_elementID){
    // Generate and Show QR Code the Page
    // Parameter: _elementID = canvas element id in the page

    qrElementID = _elementID
    loadQR()
}

function loadQR() {
    $.ajax({
        url: appBaseURL + '/jsid/authenticate/qr',
        type: 'get',
        contentType: 'application/json',
        headers: {"x-api-key": window.jsidConfig.token},
        success: function (resp) {
            csqJsidSessionId = resp.data.session_id;
            var qr = new QRious({
                element: document.getElementById(qrElementID),
                size: 100,
                value: resp.data.session_id
            });

            qrToken = resp.data.session_id;
            setTimeout(function () {
                JSIDcheckSession(qrToken);
            }, 2000);
        }
    });
}

function JSIDcreateIFrame(_element){
    console.log(_element);
    if(window.jsidConfig == undefined || window.jsidConfig.token == undefined){
        console.log("Error: Jsid not initialized");
        return;
    }

    var v = document.getElementById("div-csq-jsid-login");
    if(v != null){
        v.remove();
        return;
    }
    
    _el = document.body;
    if(window.jsidConfig.divId != undefined){
        _el = document.getElementById(window.jsidConfig.divId);
    }
    console.log(_el);

    var parentPositionLeft = 0;
    var parentPositionTop = 0;
    if(_element.nodeName != undefined){
        parentPositionLeft = _element.getBoundingClientRect().left;
        parentPositionTop = _element.getBoundingClientRect().top;
    }
    console.log(parentPositionLeft);
    console.log(parentPositionTop);
    
    const xhttp = new XMLHttpRequest();
    xhttp.onload = function() {
        htmlcode = this.responseText;
        var loginDiv = document.createElement('div');
        var loginDiv1 = document.createElement('div');
        var loginDiv2 = document.createElement('div');

        var iframe = document.createElement('iframe');
        var closeBTN = document.createElement('button');
        closeBTN.type = "button"
        closeBTN.innerHTML = "X"
        // closeBTN.setAttribute("class", "btn btn-primary")
        // loginDiv1.setAttribute("style", "text-align: center; max-width:700px;")
        
        iframe.id="iframe-csq-login"
        loginDiv.id="div-csq-jsid-login"

        // loginDiv1.appendChild(closeBTN)
        loginDiv2.appendChild(iframe)
        // loginDiv.appendChild(loginDiv1)
        loginDiv.appendChild(loginDiv2)
        _el.appendChild(loginDiv);
        
        iframe.setAttribute("style","height:" + window.innerHeight + "px;width:100%;max-width:700px;border:none;position:relative;");
        iframe.contentWindow.document.open();
        iframe.contentWindow.document.write(htmlcode);
        iframe.contentWindow.document.close();

        parentPositionLeft = parentPositionLeft - iframe.offsetWidth;
        parentPositionLeft = parentPositionLeft < 0? 0: parentPositionLeft;
        loginDiv.setAttribute("style","position:absolute;z-index:9999999;");
        // if(window.jsidConfig.position == "center"){
        loginDiv.setAttribute("style","text-align:center;");
            // parentPositionLeft = (window.innerWidth / 2) - (iframe.offsetWidth / 2);
            // parentPositionTop = (window.innerHeight / 2) - (iframe.offsetHeight / 2);
        // }
        
        // loginDiv.style.left = parentPositionLeft+'px';
        // loginDiv.style.top = parentPositionTop+'px';

    }

    xhttp.open("GET", appBaseURL + "/jsid/login?appId=" + window.jsidConfig.token, true);
    // xhttp.open("GET", "http://localhost:5002/jsid/login?appId=" + window.jsidConfig.token, true);
    xhttp.send();
}

function JSIDcheckSession(token){
    isQr = csqJsidSessionId.split(':')[0] == "QR" ? true : false;
    
    $.ajax({
        url: appBaseURL + '/jsid/session/status/' + token,
        type: 'get',
        contentType: 'application/json',
        headers: {"x-api-key": window.jsidConfig.token},
        success: function (resp) {
            console.log(resp);
            if (resp.data.session_status == "RUNNING") {
                setTimeout(function () {
                    JSIDcheckSession(token);
                }, 2000);
                return;
            }

            if (!isQr) {
                $("#modal-message-secureid-vc").modal("hide");
            }

            if (resp.data.session_status == "REJECTED") {
                if (!isQr) {
                    alert("Request regected, please try again");
                    return;
                }

                loadQR();
                return;
            }

            if (resp.data.session_status == "NO-MOBILE") {
                alert("Dear user, you are login using Jio SecureID for the firstime, please, put your mobile number and Authenticate for Once.");
                return;
            };

            if (resp.data.session_status == "INVALID-USER") {
                alert("Dear user, Please re-install you Jio SecureID application in your Mobile Phone / Tablet and re-login.");
                return;
            };

            console.log("login success");
            window.parent.JSIDLoginTrigger(resp.data.token);
            return;
        },
        error: function (resp) {
            alert("error");
            // $('#jsid-login-error').html("<strong>Error: </strong>something went wrong, please try again");
            // jsidMobile.disabled = false;
            // jsidButton.disabled = true;
            return;
        }
    });
}

function JSIDauthenticate(mobile){
    data = { mobile: mobile }

    reqStatus = false;
    $.ajax({
        url: appBaseURL + '/jsid/authenticate',
        type: 'post',
        async: false,
        dataType: 'json',
        contentType: 'application/json',
        headers: {"x-api-key": window.jsidConfig.token},
        data: JSON.stringify(data),
        success: function (resp) {
            console.log(resp);
            if (resp.status) {
                sessionToken = resp.data.session_id;
                // $('#jsid-login-error').html("");
                // $('#jsid-login-message').html("<i style='font-size: 14px;' class='fas fa-hourglass-half'></i> <strong>Login request sent to your Telegram,<br>Accept the request to continue</strong>");
                JSIDshowVC(resp.data.vc);
                setTimeout(function () {
                    JSIDcheckSession(sessionToken);
                }, 2000);
                
                chkTimeVar = 0;
                reqStatus = true;
                return true;
            }

            // $('#jsid-login-error').html("<strong>Error: </strong>" + resp.status_message);
            return false;
        },
        error: function (resp) {
            console.log(resp);
            return false;
            // $('#jsid-login-error').html("<strong>Error: </strong>something went wrong, please try again");
        }
    });

    return reqStatus;
}

function include(file) {
  
    var script  = document.createElement('script');
    script.src  = file;
    script.type = 'text/javascript';
    script.defer = true;
    
    document.getElementsByTagName('head').item(0).appendChild(script);
    
}

function JSIDshowVC(num) {
    var num1 = Math.floor(num / 100);
    var num2 = num % 100;
    if (num1 > 93) {
        num1 = num1 + 33 + 104;
    }
    else {
        num1 = num1 + 33;
    }
    if (num2 > 93) {
        num2 = num2 + 33 + 104;
    }
    else {
        num2 = num2 + 33;
    }
    var res1 = String.fromCharCode(num1);
    var res2 = String.fromCharCode(num2);
    document.getElementById("jsid-vc-char1").innerHTML = res1;
    document.getElementById("jsid-vc-char2").innerHTML = res2;
    
    $('#li-jsid-qr').hide();
    $('#li-jsid-vc').show();
}