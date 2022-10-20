import base64
from datetime import datetime
from re import L
from tokenize import group
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfinterp import resolve1
from bson.objectid import ObjectId

from pkg_imp import app, jwtTokenGenerate

class jioSign:
    import requests, json, jwt, hashlib, base64, io, uuid, datetime
    
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Cipher import PKCS1_OAEP, AES, PKCS1_v1_5
    from Cryptodome import Random

    from pkg_imp import MYSQL_TG, MONGO_JSIGN

    CSQ_SSL_CERT = "crt/livetrack1.crt"
    CSQ_SSL_KEY = "crt/livetrack1.key"
    CSQ_TOKEN_KEY = "crt/livetrack.key"

    _mongo = MONGO_JSIGN
    lastErrorCode = None
    lastErrorText = None
    
    def __init__(self, c2code, configID, clientIp, clientMac, **kargs) -> None:
        self.C2CODE = c2code
        self.CONFIG_ID = configID
        
        self.ip = clientIp,
        self.mac = clientMac

        self._mode = kargs.get('mode')
        self.setJsignConfig(configID)

        pass

    # COMMON Functions -- START
    def decodeToken(self, data):
        _key = data['key']
        _data = data['data']
        
        with open(self.CSQ_TOKEN_KEY, 'r') as f: 
            key = f.readlines()
            for i in range(0, len(key)):
                if key[i].strip() == "-----BEGIN PRIVATE KEY-----":
                    key = ''.join(key[i:])
                    break

        key = self.RSA.importKey(key)
        cipher = self.PKCS1_v1_5.new(key)
        cipher_text = self.base64.b64decode(_key).decode("utf-8")
        cipher_text = self.base64.b64decode(cipher_text)
        plain_text = cipher.decrypt(cipher_text, None)
        if not plain_text:
            return 

        key = plain_text.decode('utf-8')
        key = self.base64.b64decode(key)
        
        cipher = self.AES.new(key, self.AES.MODE_ECB)
        _data = self.base64.b64decode(_data).decode("utf-8")
        _data = self.base64.b64decode(_data)
        plaintext = cipher.decrypt(_data, None)
        if not plaintext:
            return 

        plaintext = plaintext.decode("utf8")
        if plaintext[-1:] != "]":
            plaintext = plaintext[:-1]

        return plaintext

    def writeFile(self, fname, data):
        with open(fname, 'w') as f:
            f.write(data)
            f.close()

        return 

    def encrypt(self, raw, key):
        _key = self.hashlib.sha256(key.encode()).digest()
        raw = self._pad(raw)
        iv = self.Random.new().read(self.AES.block_size)
        cipher = self.AES.new(_key, self.AES.MODE_CBC, iv)
        enc = cipher.encrypt(raw.encode())

        return self.base64.b64encode(iv + enc).decode('utf-8')

    def decrypt(self, enc, key):
        _key = self.hashlib.sha256(key.encode()).digest()
        enc = self.base64.b64decode(enc)
        iv = enc[:self.AES.block_size]
        cipher = self.AES.new(_key, self.AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[self.AES.block_size:])).decode('unicode_escape')

    def _pad(self, s):
        bs = self.AES.block_size
        return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

    def _unpad(self, s):
        return s[:-ord(s[len(s)-1:])]

    # COMMON Functions -- END
    
    
    def refreshToken(self):
        url = f"{self.JIO_BASE_URL}/session/v1.0/token"
        hdrs={'Rtoken': self.USER_TOKEN['rtoken']}
        s, r = self.apiGet(url, hdrs=hdrs)
        if not s:
            raise PermissionError

        _token_data = r.json()

        _token = _token_data['token']
        _rtoken = _token_data['rtoken']

        user = None
        exp = None

        _v = self.jwt.decode(_token, options={"verify_signature": False})
        user = _v['iden']
        exp = _v['exp']
        
        if not user or not exp:
            return False

        _data = {'token': _token, 'rtoken': _rtoken}
        _data = self.encrypt(self.json.dumps(_data), user)

        exp = self.datetime.datetime.fromtimestamp(int(exp))
        _data = {
            'exp': exp,
            'data': _data
        }

        self.MONGO_JSIGN.DB['jsign_configs'].update_many({"_id": self.CONFIG_ID}, {"$set": {"USER_TOKEN": {"exp": exp, 'data': _data['data']}}})

        return True

    def updateToken(self, data):
        _token_data = self.decodeToken(self.json.loads(data))
        self.writeFile("token_data", _token_data)
        _lPos = _token_data.rfind(']')
        _token_data = _token_data[0:_lPos + 1]
        _token_data = self.json.loads(_token_data)
        _token = _token_data[0]['token']
        _rtoken = _token_data[1]['rtoken']

        user = None
        exp = None

        _v = self.jwt.decode(_token, options={"verify_signature": False})
        user = _v['iden']
        exp = _v['exp']
        
        if not user or not exp:
            return False

        _data = {'token': _token, 'rtoken': _rtoken}
        _data = self.encrypt(self.json.dumps(_data), user)

        exp = self.datetime.datetime.fromtimestamp(int(exp))
        _data = {
            '_id': user,
            'exp': exp,
            'data': _data
        }

        self.MONGO_JSIGN.DB['jsign_configs'].update_many({"auth_email": user}, {"$set": {"USER_TOKEN": {"exp": exp, 'data': _data['data']}}})
        
        return True

    def setJsignConfig(self, configID):
        """Getting jioSign configuration for respective vendor
        """
        r = list(self.MONGO_JSIGN.DB['jsign_configs'].find({"_id": configID}))
        if len(r) == 0:
            raise Exception("Invalid configuration setting for vendor")

        r = r[0]
        self.JIO_BASE_URL = r['JIOSIGN_BASE_URL']
        self.JIO_GATEWAY_TOKEN = r['JIO_GATEWAY_TOKEN']
        self.ADMIN_EMAIL = r['auth_email']

        if self._mode != "-" and r['USER_TOKEN']['exp'] < self.datetime.datetime.utcnow():
            raise PermissionError

        self.USER_TOKEN = {}
        if r.get('USER_TOKEN') and r.get('USER_TOKEN').get('data'):
            self.USER_TOKEN = self.json.loads(self.decrypt(r['USER_TOKEN']['data'], self.ADMIN_EMAIL))

        while True:
            if not r['GATEWAY_TOKEN']:
                self.authenticateGateway()

                break

            if not r['GATEWAY_TOKEN']['exp'] or not r['GATEWAY_TOKEN']['access_token']:
                self.authenticateGateway()
                
                break

            if r['GATEWAY_TOKEN']['exp'] < self.datetime.datetime.utcnow():
                self.authenticateGateway()
                
                break

            self.JIO_API_TOKEN = r['GATEWAY_TOKEN']['access_token']
            break

        return

    def authenticateGateway(self):
        url = f"{self.JIO_BASE_URL}/token"
        headers = {
            "Authorization": self.JIO_GATEWAY_TOKEN
        }
        data = {'grant_type': 'client_credentials'}
        cert = (self.CSQ_SSL_CERT, self.CSQ_SSL_KEY)

        _t = self.datetime.datetime.utcnow()
        r = self.requests.post(url, data=data, headers=headers, cert=cert)
        if r.status_code != 200:
            raise PermissionError

        r = r.json()

        exp = _t + self.datetime.timedelta(seconds=(r['expires_in'] - 120))
        self.JIO_API_TOKEN = r['access_token']

        self.MONGO_JSIGN.DB['jsign_configs'].update_one({"_id": self.CONFIG_ID}, {"$set": {"GATEWAY_TOKEN": {"exp": exp, "access_token": r['access_token']}}})

        return 

    def getNewUUID(self):
        return str(self.uuid.uuid4())

    def setError(self, respcode = 0, code = None, text = None):
        self.lastErrorCode = code
        self.lastErrorText = text

        return

    def getHeaders(self):
        _txn = self.getNewUUID()

        return {
            'Ip-Address': self.ip[0],
            'Mac-Id': self.mac,
            'Txn': _txn,
            'Token': self.USER_TOKEN['token'],
            'Authorization': f"Bearer {self.JIO_API_TOKEN}"
        }

    def apiPost(self, url, data, files = None, format = "json", txn = None):
        _headers = self.getHeaders()
        if txn:
            _headers['Txn'] = txn

        cert = (self.CSQ_SSL_CERT, self.CSQ_SSL_KEY)

        _tempInfo = {
            'url': url,
            'data': data,
            'start_time': self.datetime.datetime.utcnow()
        }
        print(_tempInfo)
        
        if format == "form":
            r = self.requests.post(url, headers=_headers, data=data, cert=cert, files=files)
        else:
            r = self.requests.post(url, headers=_headers, json=data, cert=cert, files=files)

        _tempInfo['status_code'] = r.status_code
        _tempInfo['response'] = r.text
        _tempInfo['end_time'] = self.datetime.datetime.utcnow()
        _tempInfo['time_taken'] = (_tempInfo['end_time'] - _tempInfo['start_time']).total_seconds()
        self.MONGO_JSIGN.DB['jsign_api_logs'].insert_one(_tempInfo)
        
        if r.status_code != 200:
            if r.headers.get('Content-Type') == 'application/json':
                r1 = r.json()
                if type(r1) == list:
                    self.setError(r.status_code, r1[0].get('errcode', "UNKNOWN"), r1[0].get('message', r.text))
                    return False, r

                self.setError(r.status_code, r1.get('errcode', "UNKNOWN"), r1.get('message', r.text))

            self.setError(r.status_code, "UNKNOWN", r.text)

            return False, r

        return True, r

    def apiGet(self, url, hdrs = []):
        _headers = self.getHeaders()
        for h in hdrs:
            _headers[h] = hdrs[h]

        cert = (self.CSQ_SSL_CERT, self.CSQ_SSL_KEY)

        r = self.requests.get(url, headers=_headers, cert=cert)

        print(r)
        print(r.text)
        if r.status_code != 200:
            if r.headers.get('Content-Type') == 'application/json':
                r1 = r.json()
                if type(r1) == list:
                    self.setError(r.status_code, r1[0].get('errcode', "UNKNOWN"), r1[0].get('message', r.text))
                    return False, r

                self.setError(r.status_code, r1.get('errcode', "UNKNOWN"), r1.get('message', r.text))

            self.setError(r.status_code, "UNKNOWN", r.text)

            return False, r

        return True, r

    def apiDelete(self, url):
        _headers = self.getHeaders()
        cert = (self.CSQ_SSL_CERT, self.CSQ_SSL_KEY)

        r = self.requests.delete(url, headers=_headers, cert=cert)

        print(r)
        print(r.text)
        if r.status_code != 200:
            if r.headers.get('Content-Type') == 'application/json':
                r1 = r.json()
                if type(r1) == list:
                    self.setError(r.status_code, r1[0].get('errcode', "UNKNOWN"), r1[0].get('message', r.text))
                    return False, r

                self.setError(r.status_code, r1.get('errcode', "UNKNOWN"), r1.get('message', r.text))

            self.setError(r.status_code, "UNKNOWN", r.text)

            return False, r

        return True, r

    def createDocument(self, vender, groupName, members, file, message, **kargs):
        """Send document with base64 data of PDF"""

        url = f"{self.JIO_BASE_URL}/docmgmt/v1.0/document"
        _txn = self.getNewUUID()

        _data = {
            'name': groupName,
            'doc-owner': vender
        }

        s, r = self.apiPost(url, _data, txn=_txn)

        if not s:
            if r.headers.get('Content-Type') == 'application/json':
                return False, r.json()[0]

            return False, {"errcode": "UNKNOWN", "message": f"Unknown Error: {r.status_code}"}

        r = r.json()
        _groupId = r['groupId']

        _data = {
            'c2code': self.C2CODE,
            '_id': _groupId,
            'group_txn_id': _txn,
            'group_name': groupName,
            'message': message,
            'status': False,
            'participants': members,
            'tags': kargs.get('tags'),
            'config_id': self.CONFIG_ID,
            'user': self.ADMIN_EMAIL,
            'client_ip': self.ip,
            'client_mac': self.mac,
            't_time': self.datetime.datetime.now(),
            't_ltime': self.datetime.datetime.now()
        }

        self._mongo.DB['jsign_docs'].insert_one(_data)

        # Save data to the document group
        url = f"{self.JIO_BASE_URL}/docmgmt/v1.0/document/data"

        files=[
            ('file',(f"{groupName}.pdf", file, 'application/pdf'))
        ]

        _data = {
            'groupId': _groupId,
            'message': message,
            'participants': self.json.dumps(members)
        }

        s, r = self.apiPost(url, data = _data, files=files, format="form", txn=_txn)

        if not s:
            return s, r

        self._mongo.DB['jsign_docs'].update_one({"_id": _groupId}, {"$set": {"status": True, 't_ltime': self.datetime.datetime.now()}})

        return s, {'doc_id': _groupId, 'txn_id': _txn}

    def getDocumentInfo(self, docId):
        url = f"{self.JIO_BASE_URL}/docmgmt/v1.0/document?groupId={docId}"
        s, r = self.apiGet(url)
        
        if not s:
            if r.headers.get('Content-Type') == 'application/json':
                return False, r.json()[0]

            return False, {"errcode": "UNKNOWN", "message": f"Unknown Error: {r.status_code}"}

        return r.json()

    def getOrginalDocument(self, groupId, _docId = None, _docName = None):
        if not _docId:
            _doc = self.getDocumentInfo(groupId)
            if not _doc:
                return False 

            _docId = _doc['docs'][0]['documentId']
            _docName = _doc['docs'][0]['documentName']

        url = f"{self.JIO_BASE_URL}/docmgmt/v1.0/document/original/file?groupId={groupId}&docId={_docId}"

        s, r = self.apiGet(url)
        
        if not s:
            if r.headers.get('Content-Type') == 'application/json':
                return False, r.json()[0]

            return False, {"errcode": "UNKNOWN", "message": f"Unknown Error: {r.status_code}"}

        return True, {'data': r.content, 'file_name': _docName, 'mimetype': r.headers.get('Content-Type')}

    def getDocStatus(self, groupId):
        url = f"{self.JIO_BASE_URL}/docmgmt/v1.0/document/data/status/{groupId}"

        s, r = self.apiGet(url)
        
        if not s:
            if r.headers.get('Content-Type') == 'application/json':
                return False, r.json()[0]

            return False, {"errcode": "UNKNOWN", "message": f"Unknown Error: {r.status_code}"}

        scode = r.json()['status']
        status = None
        if scode == 1:
            status = 'Active'
        elif scode == 2:
            status = 'Deleted'
        elif scode == 3:
            status == "In Progress"
        elif scode == 4:
            status = "Completed"

        return True, {'code': scode, 'name': status}

    def getDocument(self, groupId):
        # if not self.updateSignStatus(groupId):
        #     return False

        self.getEventLog(groupId, "3,11")
        _doc = self.getDocumentInfo(groupId)
        if not _doc:
            return False 
        
        resp = {
            'status_code': _doc['status'],
            'status': _doc['status'],
            'info': {
                'group': _doc['groupName'],
                'message': _doc['message'],
                'doc_id': _doc['docs'][0]['documentId'],
                'name': _doc['docs'][0]['documentName'],
                'mime_type': _doc['docs'][0]['documentMimeType'],
                'size': _doc['docs'][0]['documentSize'],
                'created_at': _doc['createTime'],
                'update_time': _doc['updateTime'],
                'deadline': _doc['deadline'],
                'lock': _doc['lock'],
                'status': _doc['status']
            },
            'file': None
        }

        if resp['status_code'] == 2:
            return resp

        url = f"{self.JIO_BASE_URL}/docmgmt/v1.0/signed/file?groupId={groupId}"

        s, r = self.apiGet(url)

        if r.status_code == 200:
            resp['file'] = r.content

            return resp

        if r.status_code == 400:
            orgDoc = self.getOrginalDocument(groupId, resp['info']['doc_id'])
            if not orgDoc:
                return False 

            resp['file'] = orgDoc['data']
            return resp

        return False

    def getEventLog(self, groupId, events):
        url = f"{self.JIO_BASE_URL}/docmgmt/v1.0/audits?groupId={groupId}&evntIds={events}"

        s, r = self.apiGet(url)
        if r.status_code != 200:
            return False

        return r.json()

    def deleteDocument(self, user, groupId):
        _txn = str(self.uuid.uuid4())
        url = f"{self.JIO_BASE_URL}/docmgmt/v1.0/document/data/{groupId}"
        print(url)

        s, r = self.apiDelete(url)
       
        if r.status_code != 200:
            return False 

        return True

    def initSign(self, groupID, user, assLvl):
        _txn = str(self.uuid.uuid4())
        url = f"{self.JIO_BASE_URL}/docmgmt/v1.0/document/sign/initiate"
        _data = {
            'identifier': user,
            'authType': assLvl,
            'groupId': groupID,
            'action': 101,
            'tandc': "Y",
            'assuranceLevel': 2,
            'signatureType': 2
        }

        s, r = self.apiPost(url, _data, txn=_txn)
        if not r:
            return False

        return r.json()
        
    def initSignStatus(self, token):
        _txn = str(self.uuid.uuid4())
        url = f"{self.JIO_BASE_URL}/docmgmt/v1.0/document/sign/initiate/status"
        _hdrs = {
            'action-token': token
        }

        s, r = self.apiGet(url, _hdrs)
        if not r:
            return False

        return r.json()



class jSignDoc:
    import base64, io, datetime
    import base64
    from pkg_imp import MYSQL_TG, MONGO_JSIGN
    from classes.c2Crypt import crypt

    _secureAttribs = ['_data', '_jSign', '_jsignConfig']

    def __init__(self, mod, **kargs) -> None:
        """JSignDoc is for a document and it's property for Jio-Sign document.
        Modes(mod): NEW - Create new document
        READ - Read existing document

        Mandatory Args:
            c2code: Requested C2code
            ip: Requested client IP
            mac: Requested Client MAC
        """
        self._c2code = None
        self._docId = None
        self._data = None
        self._format = None
        self._title = kargs.get('title', "Document")
        self._type = "DOCUMENT"
        self._ip = None
        self._mac = None
        self._prop = None
        self._file_url = None
        self._tags = []
        self._format_prop = None
        self._members = []

        # Error Info
        lastErrorCode = None
        lastErrorText = None

        self._mongo = self.MONGO_JSIGN
        self._mod = mod

        # self.authenticate(auth)

        self._c2code = kargs['c2code']
        self._refC2code = self._c2code  #If calling vender doc from Csquare Login
    
        self._ip = kargs['ip']
        self._mac = kargs['mac']

        if self._mod == "NEW":
            """Required Parameters for NEW
                docFormat: format code the document (pre configured signing positions)
                tag: tags to be mapped to the document (coma seperated)
            """

            self._title = kargs.get('title', self._title)
            self._type = kargs.get('docType', self._type)
            self._format = kargs['docFormat']
            _tags = kargs.get('tag', "untagged").split(',')
            [self._tags.append(x.strip()) for x in _tags if x.strip() != "" and x.strip() not in self._tags]

            self._format_prop = self.loadFormat()


        self.setJsignConfig()
        self._jSign = jioSign(self._refC2code, self.vendorConfig['config_code'], self._ip, self._mac, mode=self._mod)
        self._init_time = self.datetime.datetime.utcnow()
        # self._jsign = self.jioSign(self.jsignConfig)

    def authenticate(self, auth):
        return True

    def setJsignConfig(self):
        """Getting configuration for the vendor(C2code) from MYSQL(TG) and 
        jioSign configuration for respective vendor
        """
        q = f"select c_name as vendor_name, c_email_id as email, c_mobile as mobile, n_email_mobile_flag as email_mob_flag, c_config_code as config_code from jsign_vendor_mst where \
            c_c2code = '{self._refC2code}'"
        
        r = self.MYSQL_TG.select(q)
        if len(r) == 0:
            raise Exception("Vendor not found")

        r = r[0]
        if not r['config_code']:
            raise Exception("Jio-Sign configuration not found")

        self.vendorConfig = r

        r = list(self.MONGO_JSIGN.DB['jsign_configs'].find({"_id": self.vendorConfig['config_code']}))
        if len(r) == 0:
            raise Exception("Invalid configuration setting for vendor")

        self.jsignConfig = r[0]
        return

    def loadFormat(self):
        """Loading configuration for the docFormat 
        from the mongo
        """
        r = self._mongo.find("doc_formats", {"_id": self._format})
        if len(r) == 0:
            return None

        return r[0]

    def setData(self, **kargs):
        """Setting base64 data of pdf to the class"""

        if self._mod == "READ":
            raise PermissionError("Document in Read mode")
            
        _data = kargs.get('data')
        if not _data:
            return 

        _data = self.base64.b64decode(_data.split(';')[1].split(',')[1])
        self._data = _data

        pdf_parser = PDFParser(self.io.BytesIO(_data))
        pdf_doc = PDFDocument(pdf_parser)
        self._page_count = int(resolve1(pdf_doc.catalog['Pages'])['Count'])


    def getDict(self):
        """Get the properties of the class"""

        d = self.__dict__
        
        d = dict(zip([x for x in d if x not in self._secureAttribs], \
            [d[x] for x in d if x not in self._secureAttribs]))
        
        return d

    def addMembers(self, members):
        if not self._data:
            return False, "No Data"
            
        members.insert(0, {
            'type': "OWNER",
            'email': self.vendorConfig['email']
        })

        """Adding members(signer / vendor / viewer) to the document"""
        
        if len(self._members) == 0:
            self._members.append({
                "idValue": self.jsignConfig['auth_email'],
                "idType": 1, # 1 for email, 2 for Phone
                "access": 2, # 1 Signer, 2 Viewer
                "signOrder": -1,
                "assuranceLevel": 2,
                "notifications": [{
                    "enable": 0,
                    "frequency": 1, 
                    "freq_unit": 1, # 1 Days, 2 Hours
                    "notification_type": 13 # 1 Final Notification, 2 Each sign, 5 Signing reminder
                },{
                    "enable": 0,
                    "frequency": 1, 
                    "freq_unit": 1, # 1 Days, 2 Hours
                    "notification_type": 6 # 1 Final Notification, 2 Each sign, 5 Signing reminder
                }],
                "cards": []
            })

        seq = 0
        for m in members:
            seq += 1
            _memb = {
                "idValue": None,
                "idType": 1, # 1 for email, 2 for Phone
                "access": 2, # 1 Signer, 2 Viewer
                "signOrder": seq,
                "assuranceLevel": 2,
                "notifications": [],
                "cards": []
            }

            _memb['idValue'] = m.get('email') if m.get('email') else m.get('phone')
            if not _memb['idValue']:
                raise Exception("Add email or phone")

            _memb['idType'] = 1 if m.get('email') else 2

            for _m in self._format_prop['members']:
                if m['type'] != _m['type']:
                    continue

                _memb['access'] = _m.get('access', _memb['access'])
                _memb['signOrder'] = _m.get('signOrder', _memb['signOrder'])

                _tCard = {
                    "cardType": 1,
                    "cardX": 0,
                    "cardY": 0,
                    "cardH": 0,
                    "cardW": 0,
                    "unit": "px",
                    "totalPage": self._page_count,
                    "cardPageNo": 1,
                    "cardOnPage": 2,
                    "cardColor": "#F3D87F"
                }

                for _c in _m['cards']:
                    for _t in _tCard:
                        _tCard[_t] = _c.get(_t, _tCard[_t])

                    _memb['cards'].append(_tCard)

                for _n in _m['notifications']:
                    _tNotify = {
                        "enable": 0,
                        "frequency": 1, 
                        "freq_unit": 1, # 1 Days, 2 Hours
                        "notification_type": 13 # 1 Final Notification, 2 Each sign, 5 Signing reminder
                    }

                    for _t in _tNotify:
                        _tNotify[_t] = _n.get(_t, _tNotify[_t])

                    _memb['notifications'].append(_tNotify)

            if _memb['idValue'] == self.jsignConfig['auth_email']:
                self._members[0] = _memb
            else:
                self._members.append(_memb)

    def sendDocument(self, message="Document"):
        """Send document to jioSign and will mark users who added through addMembers function"""

        if self._mod != "NEW":
            return False, "Please create new document to send"

        if len(self._members) <= 1:
            return False, "One member minimum required"

        if not self._data:
            return False, "No Data"

        r, r1 = self._jSign.createDocument(self.vendorConfig['email'], self._title, self._members, self._data, message=message, tags=self._tags)
        if r:
            self._docId = r1['doc_id']

            q = f"update jsign_vendor_mst set n_document_count = n_document_count + 1 where c_c2code = '{self._c2code}'"
            self.MYSQL_TG.execute(q)

            q = f"insert into jsign_vendor_docs (c_doc_id, c_c2code) values ('{self._docId}', '{self._c2code}')"
            self.MYSQL_TG.execute(q)

            for _t in self._tags:
                _tg = _t.replace("'", "''")
                q = f"insert into jsign_vendor_tags (c_c2code, c_tag, n_count) values ('{self._c2code}', '{_tg}', 1) \
                    ON DUPLICATE KEY UPDATE n_count = n_count + 1"
                self.MYSQL_TG.execute(q)

                q = f"insert into jsign_vendor_doc_tags (c_doc_id, c_tag) values ('{self._docId}', '{_tg}')"
                self.MYSQL_TG.execute(q)


            return self._docId

        self.setError(self._jSign.lastErrorCode, self._jSign.lastErrorText)
        return False

    def getB64Data(self):
        """Read base64 data of the document"""

        if not self._data:
            return None

        return f"data:application/pdf;base64,{self.base64.b64encode(self._data).decode('utf-8')}"

    def setError(self, code = None, text = None):
        self.lastErrorCode = code
        self.lastErrorText = text

    def updateToken(self, data):
        return self._jSign.updateToken(data)

    def getDocStatus(self, groupID):
        return self._jSign.getDocStatus(groupID)

    def initSign(self, groupID, flag):
        _doc = self._mongo.DB['jsign_docs'].find_one({"_id": groupID})
        
        _user = None
        for _p in _doc['participants']:
            if _p['signOrder'] == flag:
                _user = _p
                break

        if not _user:
            return False

        if _user['access'] != 1:
            return False

        r = self._jSign.initSign(groupID, _user['idValue'], 2 if _user['idType'] == 1 else 3)
        if not r:
            return False

        _d = {
            'groupID': groupID,
            'flag': flag,
            'user': _user,
            'response': r,
            'time': self.datetime.datetime.utcnow()
        }

        _r = self._mongo.DB['jsign_doc_sign_request'].insert_one(_d)
        _reqID = str(_r.inserted_id)
        if r.get('status', "COMPLETED") == "COMPLETED":
            return False

        return _reqID

    def initSignStatus(self, id):
        _r = list(self._mongo.DB['jsign_doc_sign_request'].find({'_id': ObjectId(id)}))
        if not _r:
            return False

        if _r['response'].get('status') == 'COMPLETED':
            return False

        if not _r['response'].get('action-token'):
            return False

        r = self._jSign.initSignStatus(_r['response'].get('action-token'))

        return 

    def app_register(self, key):
        _q = f"select c_key from jsign_vendor_mst where c_c2code = '{self._c2code}' and n_active = 1"
        _r = self.MYSQL_TG.select(_q)
        if len(_r) == 0:
            return False, None

        if not key or not _r[0]['c_key']:
            return False, None

        if key != _r[0]['c_key']:
            return False, None

        _c2Crypt = self.crypt()
        _token = _c2Crypt.getRandomHash()
        print(_token)

        self.MONGO_JSIGN.DB["app_tokens"].delete_many({'_id': self._c2code})
        self.MONGO_JSIGN.DB["app_tokens"].insert_one({'_id': self._c2code, 
                        'clientSecret': _token, 'time': self.datetime.datetime.utcnow()})

        return True, _token

    def app_login(self, secret):
        _r = self.MONGO_JSIGN.DB["app_tokens"].find_one({'_id': self._c2code, 
                        'clientSecret': secret})

        if not _r:
            return False, None

        if _r.get('clientSecret') != secret:
            return False, None
        
        _sessionId = self.MONGO_JSIGN.DB["app_sessions"].insert_one({'c2code': self._c2code, 
            'clientSecret': secret, 'time': self.datetime.datetime.utcnow()})

        _sessionId = str(_sessionId.inserted_id)

        return True, {'session_id': _sessionId, 'c2code': self._c2code}

    def app_logout(self, sessionID):
        self.MONGO_JSIGN.DB["app_sessions"].update_one({'_id': sessionID}, { "$set": { "end_time": self.datetime.datetime.utcnow()}})

        return True
        
    def app_check_session(self, sessionID):
        _r = self.MONGO_JSIGN.DB["app_sessions"].find_one({'_id': ObjectId(sessionID)})
        if not _r:
            return False

        if _r.get('end_time'):
            return False

        return True

    def get_total_sec(self):
        _diff = self.datetime.datetime.utcnow() - self._init_time
        return _diff.total_seconds()

    def update_total_doc_time(self):
        if not self._docId:
            return 

        _t = {
            '_': "send_time",
            'doc_id': self._docId,
            'start_time': self._init_time,
            'total_seconds': self.get_total_sec()
        }

        _r = self.MONGO_JSIGN.DB["jsign_docs_logs"].insert_one(_t)

