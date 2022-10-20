import os
env="prod"

CSQ_SSO_BASE_URL = "https://login.livetrack.in"
APP_HOME_URL = "csq-lic/web/licenseManagement"


# Database connections
MYSQL_CONN_POOL_SIZE=5
MONGO_CONN_POOL_SIZE=5

MYSQL_CONN_TG={
    'host' : 'qa-liveconnect.mysql.database.azure.com',
    'database' : 'telegram',
    'user' : 'obuk@qa-liveconnect',
    'password' : 'Orderbuklc123'
}

MONGO_JIOSIGN_HOST = "mongodb://qa-jiosign:c$jiosign!##c2@10.2.68.4/admin"
MONGO_JIOSIGN_DB = "qa_jiosign"

MONGO_JIOSID_HOST = "mongodb://qa-jiosecureid:c#j!0$ecure!d@10.2.68.4/admin"
MONGO_JIOSID_DB = "qa_jio_secure_id"

MONGO_SHORT_URL_HOST = "mongodb://qa-jiosign:c$jiosign!##c2@10.2.68.4/admin"
MONGO_SHORT_URL_DB = "qa_jiosign"

CSQ_ENCRYPT_KEY = "Em4fLT0Nyq126F7K"
JWT_ENCRYPT_KEY = "Em4fLT0Nyq126F7K"
JWT_ENCRYPT_IV = "1827364551991827"

SHOURT_BASE_URL = "http://localhost:5002/s"

MONGO_CSQUARE_HOST = "mongodb://csq-tg-bot:V2XM9ztgpAJM5HDAPdqfwAKNwO7MWiS5oaOtiGADi5FVarFEL97Rpg9zpns4QIobj4h0JiDslcAVLclAkx4YNQ==@csq-tg-bot-jioindiawest.mongo.cosmos.azure.com:10255/?ssl=true&replicaSet=globaldb&retrywrites=false&maxIdleTimeMS=120000&appName=@csq-tg-bot@"
MONGO_CSQUARE_DB = "csquare"

# LT_BASE_URL = "http://localhost:53743/api"
LT_BASE_URL = "https://api.livetrack.in/api"

_env = os.environ
env1 = {}
for _ in _env:
    env1[_] = _env[_]

if 'env' in env1:
    env = env1['env']

if env == "prod":
    MYSQL_CONN_POOL_SIZE=32
    MONGO_CONN_POOL_SIZE=32

    MYSQL_CONN_TG={
        'host' : 'liveconnect.mysql.database.azure.com',
        'database' : 'telegram',
        'user' : 'obuk@liveconnect',
        'password' : 'Orderbuklc123'
    }

    MONGO_JIOSID_HOST = "mongodb://prod-jiosecureid:c2j!0$ecure!dP$0d@10.2.68.4/admin"
    MONGO_JIOSID_DB = "prod_jio_secure_id"

    MONGO_JIOSIGN_HOST = "mongodb://csq-tg-bot:V2XM9ztgpAJM5HDAPdqfwAKNwO7MWiS5oaOtiGADi5FVarFEL97Rpg9zpns4QIobj4h0JiDslcAVLclAkx4YNQ==@csq-tg-bot-jioindiawest.mongo.cosmos.azure.com:10255/?ssl=true&replicaSet=globaldb&retrywrites=false&maxIdleTimeMS=120000&appName=@csq-tg-bot@"
    MONGO_JIOSIGN_DB = "prod_doc_jsign"

    MONGO_SHORT_URL_HOST = "mongodb://csq-tg-bot:V2XM9ztgpAJM5HDAPdqfwAKNwO7MWiS5oaOtiGADi5FVarFEL97Rpg9zpns4QIobj4h0JiDslcAVLclAkx4YNQ==@csq-tg-bot-jioindiawest.mongo.cosmos.azure.com:10255/?ssl=true&replicaSet=globaldb&retrywrites=false&maxIdleTimeMS=120000&appName=@csq-tg-bot@"
    MONGO_SHORT_URL_DB = "prod_short_url"

    MONGO_CSQUARE_HOST = "mongodb://csq-tg-bot:V2XM9ztgpAJM5HDAPdqfwAKNwO7MWiS5oaOtiGADi5FVarFEL97Rpg9zpns4QIobj4h0JiDslcAVLclAkx4YNQ==@csq-tg-bot-jioindiawest.mongo.cosmos.azure.com:10255/?ssl=true&replicaSet=globaldb&retrywrites=false&maxIdleTimeMS=120000&appName=@csq-tg-bot@"
    MONGO_CSQUARE_DB = "csquare"

    SHORT_BASE_URL = "https://1c2.in/s"
    
