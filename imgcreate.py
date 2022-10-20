from PIL import Image, ImageDraw, ImageFont
def main():
    frame = "assets/images/diwali-2.png"
    user = "assets/images/user.jpg"
    fontFile = "assets/fonts/OpenSans-BoldItalic.ttf"

    font = ImageFont.truetype(fontFile, size=34)
    texts = ["Vishnu"]

    frame = Image.open(frame)
    user = Image.open(user)
    finalImg = Image.new('RGB', frame.size, color = 'white')
    canvas = ImageDraw.Draw(finalImg)

    user = user.resize((620, 310))
    finalImg.paste(user, (250, 1030))
    finalImg.paste(frame, (0, 0), frame)

    tmpY = 1520
    for t in texts:
        canvas.text((380, tmpY), t, font=font, fill='#ffffff')
        tmpY += 55


    finalImg.show()

main()