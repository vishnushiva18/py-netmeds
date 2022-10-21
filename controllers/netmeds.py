from flask import (render_template, request,
                   url_for, redirect)
from pkg_imp import app, requests, MONGO_CSQUARE
from PIL import Image, ImageDraw, ImageFont, ExifTags
import base64, io, uuid

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
    
    frame = f".{frame}"
    with app.open_resource(frame, 'rb') as f:
        frame = f.read()

    fontFile = "./assets/fonts/OpenSans-BoldItalic.ttf"
    with app.open_resource(fontFile, 'rb') as f:
        fontFile = f.read()

    font = ImageFont.truetype(io.BytesIO(fontFile), size=34)
    frame = Image.open(io.BytesIO(frame))
    user = base64.b64decode(d['user_img'].split(';')[1].split(',')[1])
    user = Image.open(io.BytesIO(user))
    exif = None
    if user._getexif():
        exif=dict((ExifTags.TAGS[k], v) for k, v in user._getexif().items() if k in ExifTags.TAGS)

    if exif and exif.get('Orientation'):
        orientation = exif.get('Orientation')
        if orientation == 8:
            user=user.rotate(90, expand=True)
        elif orientation == 3:
            user=user.rotate(180, expand=True)
        elif orientation == 6:
            user=user.rotate(270, expand=True)

    finalImg = Image.new('RGB', frame.size, color = 'white')
    canvas = ImageDraw.Draw(finalImg)
    
    user = user.resize((276, 276))
    finalImg.paste(user, (116, 1540))
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

    
@app.route('/netmeds/diwali/create/<empid>', methods=['GET', 'POST'])
def netmeds_diwali_create(empid):
    if request.method == "GET":
        return render_template('netmeds/diwali-create.html', empid=empid)

    frame = f"/assets/images/diwali-2.png"
    d = request.json
    texts = [d['name']]
    
    frame = f".{frame}"
    with app.open_resource(frame, 'rb') as f:
        frame = f.read()

    fontFile = "./assets/fonts/OpenSans-BoldItalic.ttf"
    with app.open_resource(fontFile, 'rb') as f:
        fontFile = f.read()

    font = ImageFont.truetype(io.BytesIO(fontFile), size=34)
    frame = Image.open(io.BytesIO(frame))
    user = base64.b64decode(d['user_img'].split(';')[1].split(',')[1])
    user = Image.open(io.BytesIO(user))
    exif = None
    if user._getexif():
        exif=dict((ExifTags.TAGS[k], v) for k, v in user._getexif().items() if k in ExifTags.TAGS)

    if exif and exif.get('Orientation'):
        orientation = exif.get('Orientation')
        if orientation == 8:
            user=user.rotate(90, expand=True)
        elif orientation == 3:
            user=user.rotate(180, expand=True)
        elif orientation == 6:
            user=user.rotate(270, expand=True)

    finalImg = Image.new('RGB', frame.size, color = 'white')
    canvas = ImageDraw.Draw(finalImg)
    
    user = user.resize((620, 310))
    finalImg.paste(user, (250, 1030))
    finalImg.paste(frame, (0, 0), frame)

    tmpY = 1520
    for t in texts:
        canvas.text((380, tmpY), t, font=font, fill='#ffffff')
        tmpY += 55


    fileId = str(uuid.uuid4())
    try:
        finalImg.save(f"./output/{fileId}.jpg", format="JPEG")
    except Exception as e:
        print(e)
        pass

    bufferedFinal = io.BytesIO()
    finalImg.save(bufferedFinal, format="JPEG")
    final_str = bytes("data:image/jpeg;base64,", encoding='utf-8') + base64.b64encode(bufferedFinal.getvalue())

    d['user_img'] = None
    MONGO_CSQUARE.DB["netmeds_microsite_log"].insert_one(d)
    return {'img': final_str.decode("utf-8")}


@app.route('/netmeds/microsite/update', methods=['POST'])
def netmeds_microsite_update():
    d = request.json
    print(d)
    MONGO_CSQUARE.DB["netmeds_microsite_log"].insert_one(d)

    return {}

