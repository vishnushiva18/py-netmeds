from flask import (render_template, request,
                   url_for, redirect)
from pkg_imp import app, requests, MONGO_CSQUARE
from PIL import Image, ImageDraw, ImageFont
import base64, io

@app.route('/netmeds/wecare', methods=['GET'])
def netmeds_wecare():
    lang = [{
        't': "Hindi | हिन्दी",
        'h': "/netmeds/wecare/hindi"
    },
    {
        't': "Marathi | मराठी",
        'h': "/netmeds/wecare/marathi"
    },
    {
        't': "Tamil | தமிழ்",
        'h': "/netmeds/wecare/tamil"
    },
    {
        't': "Telugu | తెలుగు",
        'h': "/netmeds/wecare/telugu"
    },
    {
        't': "Malayalam | മലയാളം",
        'h': "/netmeds/wecare/malayalam"
    },
    {
        't': "Bangla | বাংলা",
        'h': "/netmeds/wecare/bangla"
    },
    {
        't': "Odia | ଓଡିଆ",
        'h': "/netmeds/wecare/odia"
    },{
        't': "English",
        'h': "/netmeds/wecare/english"
    }]

    return render_template('netmeds/wecare.html', lang=lang)

@app.route('/netmeds/wecare/<lang>', methods=['GET'])
def netmeds_wecare_lang(lang):
    img = f"/assets/images/WeCare-Diwali_{lang}.png"
    return render_template('netmeds/wecare-create.html', lang=lang, img=img)

@app.route('/netmeds/wecare/<lang>/create', methods=['GET', 'POST'])
def netmeds_wecare_lang_create(lang):
    frame = f"/assets/images/WeCare-Diwali_{lang}.png"
    if request.method == "GET":
        return render_template('netmeds/wecare-create.html', lang=lang, img=frame)

    d = request.json
    texts = [d['name'], d['shop'], d['phone'], d['location']]
    
    fontFile = "./assets/fonts/OpenSans-BoldItalic.ttf"
    font = ImageFont.truetype(fontFile, size=34)
    frame = Image.open(f".{frame}")
    user = base64.b64decode(d['user_img'].split(';')[1].split(',')[1])
    user = Image.open(io.BytesIO(user))

    finalImg = Image.new('RGB', frame.size, color = 'white')
    canvas = ImageDraw.Draw(finalImg)
    
    user = user.resize((276, 276))
    finalImg.paste(user, (116, 1552))
    finalImg.paste(frame, (0, 0), frame)

    tmpY = 1540
    for t in texts:
        canvas.text((420, tmpY), t, font=font, fill='#ffffff')
        tmpY += 55


    bufferedFinal = io.BytesIO()
    finalImg.save(bufferedFinal, format="JPEG")
    final_str = bytes("data:image/jpeg;base64,", encoding='utf-8') + base64.b64encode(bufferedFinal.getvalue())

    d['user_img'] = None
    MONGO_CSQUARE.DB["netmeds_microsite_log"].insert_one(d)
    return {'img': final_str.decode("utf-8")}

@app.route('/netmeds/diwali', methods=['GET', 'POST'])
def netmeds_diwali():
    if request.method == "GET":
        return render_template('netmeds/diwali.html')

    d = request.json
    empId = d['empId']
    return {}

    
@app.route('/netmeds/diwali/create/<empid>', methods=['GET'])
def netmeds_diwali_create(empid):
    return render_template('netmeds/diwali-create.html', empid=empid)

@app.route('/netmeds/microsite/update', methods=['POST'])
def netmeds_microsite_update():
    d = request.json
    print(d)
    MONGO_CSQUARE.DB["netmeds_microsite_log"].insert_one(d)

    return {}

