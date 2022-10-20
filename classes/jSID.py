class jioSecure:
    import requests, json
    import uuid, random, string
    import secrets, hashlib, base64
    import datetime
    from classes.c2Crypt import crypt
    from pkg_imp import MONGO_JSID

    JIO_CERTIFICATE_LEVEL = "ADVANCED"
    
    CSQ_SSL_CERT = "crt/livetrack1.crt"
    CSQ_SSL_KEY = "crt/livetrack1.key"
    
    CSQ_APP_LABEL = None
    JIO_API_TOKEN = None

    def __init__(self, appId, authToken) -> None:
        self.CSQ_APP_TOKEN = authToken
        self.CSQ_APP_ID = appId

        self.csqAuthenticate()
        self.getConfig()

        self.JIO_BASE_URL = self.CONFIG['base_url']
        self.JIO_TOKEN_URL = self.CONFIG['token_url']
        self.JIO_RP_UUID = self.CONFIG['rp_uid']
        self.JIO_RP_NAME = self.CONFIG['rp_name']
    
        self.CSQ_REQUEST = {}
        pass

    def getConfig(self):
        r = list(self.MONGO_JSID.DB["config"].find({"_id": "jsid-config"}))
        if len(r) == 0:
            raise Exception("configuration not found")

        self.CONFIG = r[0]

    def csqAuthenticate(self):
        valid = False
        r = list(self.MONGO_JSID.DB["app_tokens"].find({"_id": self.CSQ_APP_ID, "token": self.CSQ_APP_TOKEN}))
        if len(r) == 0:
            raise PermissionError

        self.CSQ_APP_LABEL = r[0]['app_label']
        return True

    def securePost(self, url, data):
        url = f"{self.JIO_BASE_URL}{url}"
        headers = {
            'Authorization': f'Bearer {self.JIO_API_TOKEN}'
        }
        cert = (self.CSQ_SSL_CERT, self.CSQ_SSL_KEY)
        
        _lg = {
            'url': url,
            'method': 'POST',
            'start_time': self.datetime.datetime.utcnow()
        }
        
        r = self.requests.post(url, headers = headers, cert=cert, json=data)
        
        _lg['end_time'] = self.datetime.datetime.utcnow()
        _lg['status_code'] = r.status_code
        _lg['time_taken'] = (_lg['end_time'] - _lg['start_time']).total_seconds()
        self.MONGO_JSID.DB["secure_api_logs"].insert_one(_lg)

        return r

    def secureGet(self, url):
        url = f"{self.JIO_BASE_URL}{url}"
        headers = {
            'Authorization': f'Bearer {self.JIO_API_TOKEN}'
        }
        cert = (self.CSQ_SSL_CERT, self.CSQ_SSL_KEY)
        
        _lg = {
            'url': url,
            'method': 'GET',
            'start_time': self.datetime.datetime.utcnow()
        }

        r = self.requests.get(url, headers = headers, cert=cert)

        _lg['end_time'] = self.datetime.datetime.utcnow()
        _lg['status_code'] = r.status_code
        _lg['time_taken'] = (_lg['end_time'] - _lg['start_time']).total_seconds()
        self.MONGO_JSID.DB["secure_api_logs"].insert_one(_lg)
        
        return r

    def secureAuthenticate(self, mobile, displayText):
        self.CSQ_REQUEST['_id'] = str(self.uuid.uuid4())
        self.CSQ_REQUEST['method'] = "AUTHENTICATE"
        self.CSQ_REQUEST['time'] = self.datetime.datetime.utcnow()
        self.CSQ_REQUEST['sessionId'] = None
        self.CSQ_REQUEST['status'] = {}

        if not self.getToken():
            self.CSQ_REQUEST['status']['status_code'] = 0
            self.CSQ_REQUEST['status']['response_type'] = "text"
            self.CSQ_REQUEST['status']['response'] = "secureId token generation failed"
            self.updateSession()

            return False, "secureId token generation failed"


        randomHash = self.secrets.token_hex(16)
        randomHash = self.hashlib.sha256(randomHash.encode()).digest()
        encodedHash = self.base64.b64encode(randomHash).decode('utf-8')
        vc = self.calculateVC(randomHash)
        
        nonce = ''.join(self.random.choices(self.string.ascii_letters, k=6))
        
        self.CSQ_REQUEST['hash'] = encodedHash
        self.CSQ_REQUEST['hashType'] = "SHA256"
        self.CSQ_REQUEST['displayText'] = displayText
        self.CSQ_REQUEST['nonce'] = nonce
        
        data = {
            "relyingPartyUUID": self.JIO_RP_UUID,
            "relyingPartyName": self.JIO_RP_NAME,
            "certificateLevel": self.JIO_CERTIFICATE_LEVEL,
            "hash": self.CSQ_REQUEST['hash'],
            "hashType": self.CSQ_REQUEST['hashType'],
            "displayText": self.CSQ_REQUEST['displayText'],
            "nonce": self.CSQ_REQUEST['nonce'],
            "requestProperties": {
                "vcChoice": True
            }
        }

        r = self.securePost(f"/requestForAuthAuthz/authentication/pno/IN/{mobile}", data)

        self.CSQ_REQUEST['status']['status_code'] = r.status_code
        self.CSQ_REQUEST['status']['response_type'] = r.headers.get("Content-Type", None)
        self.CSQ_REQUEST['status']['response'] = r.text

        if r.status_code != 200:
            print(r.text)
            self.updateSession()
            errorText = "Unknown error"
            if r.status_code == 400:
                errorText = "mobile not registed with secureId"
                if r.json().get('errorCd') == "4109":
                    errorText = "Please wait for previous request to complete or Reject from pending requests in Jio SecureID."

            if r.status_code == 401:
                errorText = "token authentication failed with secureId"

            return False, errorText

        r = r.json()
        self.CSQ_REQUEST['status']['response'] = r
        self.CSQ_REQUEST['sessionId'] = r['sessionId'] 
        self.updateSession()

        self.MONGO_JSID.DB["secure_sessions"].insert_one({"_id": r['sessionId'], 'user': {'mobile': mobile, 'CN': None}, 'status': None, 'time': self.datetime.datetime.utcnow()})
        return True, {'session_id': r['sessionId'], 'vc': vc}

    def generateToken(self):
        _t = self.datetime.datetime.utcnow()

        headers = {
            "Authorization": f"Basic {self.CONFIG['gateway_token']}"
        }
        data = {'grant_type': 'client_credentials'}

        cert = (self.CSQ_SSL_CERT, self.CSQ_SSL_KEY)
        _lg = {
            'url': self.JIO_TOKEN_URL,
            'method': 'GATEWAY',
            'start_time': self.datetime.datetime.utcnow()
        }

        r = self.requests.post(self.JIO_TOKEN_URL, data=data, headers=headers, cert=cert)
        _lg['end_time'] = self.datetime.datetime.utcnow()
        _lg['status_code'] = r.status_code
        _lg['time_taken'] = (_lg['end_time'] - _lg['start_time']).total_seconds()
        self.MONGO_JSID.DB["secure_api_logs"].insert_one(_lg)
        
        if r.status_code != 200:
            return False
        
        r = r.json()
        self.JIO_API_TOKEN = r['access_token']

        r['requested_time'] = _t
        r['expiry_time'] = _t + self.datetime.timedelta(seconds=(r['expires_in'] - 30))
        self.JIO_API_TOKEN_INFO = r

        _r = list(self.MONGO_JSID.DB["config"].find({'_id': "access_token"}))
        if len(_r) == 0:
            self.MONGO_JSID.DB["config"].insert_one({'_id': 'access_token', 'token': r})
        else:
            self.MONGO_JSID.DB["config"].update_one({'_id': "access_token"}, { "$set": { "token": r}})

        return True

    def getToken(self):
        _r = list(self.MONGO_JSID.DB["config"].find({'_id': "access_token"}))
        if len(_r) == 0:
            return self.generateToken()

        _r = _r[0]['token']
        if _r['expiry_time'] < self.datetime.datetime.utcnow():
            return self.generateToken()

        self.JIO_API_TOKEN = _r['access_token']
        self.JIO_API_TOKEN_INFO = _r
        return True

    def sessionStatus(self, sessionId):
        url = f"/getSessionStatus/session/{sessionId}?timeOut=1"

        if not self.getToken():
            return False, "secureId token generation failed"

        r = self.secureGet(url) 
        if r.status_code == 400:
            return False, "request not found", None

        if r.status_code != 200:
            print(r.status_code)
            print(r.text)
            return False, "Unknown error", None

        # open('response.json', 'w').write(r.text)
        r = r.json()
        self.MONGO_JSID.DB["secure_sessions"].update_one( {"_id": sessionId}, {"$set": {"status": r}})

        sessionState = r['state']
        if sessionState == "COMPLETE":
            if not r['result']:
                return True, sessionState, None

            sessionState = r['result']
            if isinstance(sessionState, str):
                if sessionState == "USER_REFUSED" or sessionState == "TIMEOUT" or sessionState == "DOCUMENT_UNUSABLE" or sessionState == "WRONG_VC" or sessionState == '{\"endResult\":\"WRONG_VC\"}' or sessionState == '{"endResult":"WRONG_VC"}':
                    return True, sessionState, None

                sessionState = self.json.loads(sessionState)

            sessionState = sessionState['endResult']

        _prop = None
        if sessionState == "OK":
            _prop = self.getSessionCertProp(sessionId)
            # validate user certificate
            if _prop.get('validTill') < self.datetime.datetime.utcnow():
                return False, "TIMEOUT", None

            _r = list(self.MONGO_JSID.DB["jsid_users"].find({"_id": _prop.get('CN')}))
            _r1 = list(self.MONGO_JSID.DB["secure_sessions"].find({"_id": sessionId}))[0]
            if len(_r) == 0:
                self.MONGO_JSID.DB["jsid_users"].insert_one({"_id": _prop.get('CN'), 'mobile': _r1.get('user').get('mobile'), 'created_on': self.datetime.datetime.utcnow(), 'last_login': self.datetime.datetime.utcnow()})
            elif not _r[0]['mobile']:
                self.MONGO_JSID.DB["jsid_users"].update_one({"_id": _prop.get('CN')}, {'$set': {"mobile": _r1.get('user').get('mobile'), 'last_login': self.datetime.datetime.utcnow()}})
                
            _prop = self.getSessionCertProp(sessionId)
            self.MONGO_JSID.DB["secure_sessions"].update_one({"_id": sessionId}, {"$set": {"user.CN": _prop.get('CN')}})

        return True, sessionState, _prop

    def updateSession(self):
        self.MONGO_JSID.DB["app_sessions"].insert_one(self.CSQ_REQUEST)

    def calculateVC(self, decodedHash):
        vc = self.hashlib.sha256(decodedHash).digest()[-2::]
        vc = int.from_bytes(vc, "big") % 10000
        return vc

    def logAppDownload(self, mobile, type):
        d = {
            'mobile': mobile,
            'type': type,
            'time': self.datetime.datetime.utcnow()
        }

        # self._mongo.insertOne("app_downloads", d)

        return

    def generateQRCode(self, displayText):
        self.CSQ_REQUEST['_id'] = str(self.uuid.uuid4())
        self.CSQ_REQUEST['method'] = "AUTHENTICATE"
        self.CSQ_REQUEST['time'] = self.datetime.datetime.utcnow()
        self.CSQ_REQUEST['sessionId'] = None
        self.CSQ_REQUEST['status'] = {}

        if not self.getToken():
            self.CSQ_REQUEST['status']['status_code'] = 0
            self.CSQ_REQUEST['status']['response_type'] = "text"
            self.CSQ_REQUEST['status']['response'] = "secureId token generation failed"
            self.updateSession()

            return False, "secureId token generation failed"


        randomHash = self.secrets.token_hex(16)
        randomHash = self.hashlib.sha256(randomHash.encode()).digest()
        encodedHash = self.base64.b64encode(randomHash).decode('utf-8')
        vc = self.calculateVC(randomHash)
        
        nonce = ''.join(self.random.choices(self.string.ascii_letters, k=6))
        
        self.CSQ_REQUEST['hash'] = encodedHash
        self.CSQ_REQUEST['hashType'] = "SHA256"
        self.CSQ_REQUEST['displayText'] = displayText
        self.CSQ_REQUEST['nonce'] = nonce
        
        data = {
            "relyingPartyUUID": self.JIO_RP_UUID,
            "relyingPartyName": self.JIO_RP_NAME,
            "certificateLevel": self.JIO_CERTIFICATE_LEVEL,
            "hash": self.CSQ_REQUEST['hash'],
            "hashType": self.CSQ_REQUEST['hashType'],
            "displayText": self.CSQ_REQUEST['displayText'],
            "nonce": self.CSQ_REQUEST['nonce'],
            "requestProperties": {
                "vcChoice": True
            }
        }

        r = self.securePost(f"/requestForAuthAuthz/authentication/qr/IN/code", data)

        self.CSQ_REQUEST['status']['status_code'] = r.status_code
        self.CSQ_REQUEST['status']['response_type'] = r.headers.get("Content-Type", None)
        self.CSQ_REQUEST['status']['response'] = r.text

        if r.status_code != 200:
            self.updateSession()
            errorText = "Unknown error"
            if r.status_code == 400:
                errorText = "mobile not registed with secureId"

            if r.status_code == 401:
                errorText = "token authentication failed with secureId"

            return False, errorText

        r = r.json()
        self.CSQ_REQUEST['status']['response'] = r
        self.CSQ_REQUEST['sessionId'] = r['sessionId'] 
        self.updateSession()

        self.MONGO_JSID.DB["secure_sessions"].insert_one({"_id": r['sessionId'], 'user': {'mobile': None, 'CN': None}, 'status': None, 'time': self.datetime.datetime.utcnow()})
        return True, {'session_id': r['sessionId'], 'vc': vc}

    def getSessionCertProp(self, id):
        r = list(self.MONGO_JSID.DB["secure_sessions"].find({"_id": id}))
        if len(r) == 0:
            return None

        r = r[0]
        if r['status']['state'] != "COMPLETE":
            return None

        cert = r['status']['cert']
        if not cert:
            return None

        cert = self.json.loads(cert)
        if not cert:
            return None

        cert = cert['value']
        _crypt = self.crypt()
        # open('test.crt', 'wb').write(_crypt.base64.b64decode(cert))
        _prop = _crypt.getX509DerProp(cert)
        _prop['mobile'] = None
        _r = list(self.MONGO_JSID.DB["jsid_users"].find({"_id": _prop.get('CN')}))
        if len(_r) > 0:
            _prop['mobile'] = _r[0]['mobile']

        return _prop