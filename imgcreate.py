from PIL import Image, ImageDraw, ImageFont
def main():
    frame = "assets/images/WeCare-Diwali_english.png"
    user = "assets/images/user.jpg"
    fontFile = "assets/fonts/OpenSans-BoldItalic.ttf"

    font = ImageFont.truetype(fontFile, size=34)
    texts = ["Vishnu", "C-Square", "9567764045", "kochi"]

    frame = Image.open(frame)
    user = Image.open(user)
    finalImg = Image.new('RGB', frame.size, color = 'white')
    canvas = ImageDraw.Draw(finalImg)

    user = user.resize((276, 276))
    finalImg.paste(user, (116, 1552))
    finalImg.paste(frame, (0, 0), frame)

    tmpY = 1540
    for t in texts:
        canvas.text((420, tmpY), t, font=font, fill='#ffffff')
        tmpY += 55


    finalImg.show()

main()