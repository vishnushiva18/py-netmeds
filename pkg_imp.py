from flask import redirect, url_for, request, session, abort, render_template, abort
import flask
from flask_cors import CORS

import json, base64, requests, datetime, decimal

import config
from classes.dbConnector import mongoConnector

from functools import wraps

app = flask.Flask(__name__)
CORS(app)
app.config.from_object(__name__)
app.config['JSON_SORT_KEYS'] = False
app.config['SECRET_KEY'] = "vishnu-csq-jio-sign-key"

class MyJSONEncoder(flask.json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime.datetime):
            return o.__str__()
        if isinstance(o, datetime.date):
            return o.__str__()
        if isinstance(o, decimal.Decimal):
            return float(o.__str__())
            
app.json_encoder = MyJSONEncoder

MONGO_CSQUARE = mongoConnector(config.MONGO_CSQUARE_HOST, config.MONGO_CSQUARE_DB, config.MONGO_CONN_POOL_SIZE)

