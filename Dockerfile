FROM ubuntu:20.04

EXPOSE 5000

WORKDIR /app

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get clean all
RUN apt-get install -y python3
RUN apt-get install -y python3-pip
RUN pip3 install --upgrade pip
RUN pip3 install gunicorn[gevent]
# RUN apt-get install -y pkg-config
# RUN apt-get install -y libsdl-pango-dev
# RUN apt-get install -y wkhtmltopdf
RUN apt install -y python3-cffi python3-brotli libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
# RUN apt install -y libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
# RUN apt-get install -y python3-wheel python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info





COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

CMD gunicorn --worker-class gevent --workers 8 --bind 0.0.0.0:5000 wsgi:app --max-requests 10000 --timeout 1000 --keep-alive 5 --log-level info
# CMD ["python3", "/app/app.py"]
