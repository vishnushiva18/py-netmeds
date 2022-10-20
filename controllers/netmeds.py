from flask import (render_template, request,
                   url_for)
from pkg_imp import app, requests, MONGO_CSQUARE

@app.route('/netmeds/wecare', methods=['GET'])
def netmeds_wecare():
    lang = [{
        't': "Hindi",
        'h': "/netmeds/wecare/hindi"
    },{
        't': "English",
        'h': "/netmeds/wecare/english"
    },{
        't': "Malayalam",
        'h': "/netmeds/wecare/malayalam"
    }]

    return render_template('netmeds/wecare.html', lang=lang)

@app.route('/netmeds/wecare/<lang>', methods=['GET'])
def netmeds_wecare_lang(lang):
    return render_template('netmeds/wecare-process.html', lang=lang)

@app.route('/netmeds/wecare/<lang>/create', methods=['GET'])
def netmeds_wecare_lang_create(lang):
    img = f"/assets/images/WeCare-Diwali_{lang}.png"
    return render_template('netmeds/wecare-create.html', lang=lang, img=img)

@app.route('/netmeds/microsite/update', methods=['POST'])
def netmeds_microsite_update():
    d = request.json
    MONGO_CSQUARE.DB["netmeds_microsite_log"].insert_one(d)

    return {}

