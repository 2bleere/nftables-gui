FROM python:3.11
LABEL org.opencontainers.image.source=https://github.com/alegarsan11/nftables-gui
LABEL org.opencontainers.image.description="nftables web GUI with docker support"
LABEL org.opencontainers.image.licenses=GPLV3
COPY . /opt/app
WORKDIR /opt/app/nftables-frontend
# Install nftables system lib first, then pip packages
RUN apt-get update && apt-get install -y nftables python3-nftables libnftables1 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir \
    "numpy<2" \
    "falcon<3" \
    gunicorn \
    hug \
    flask==3.0.1 \
    "flask-bootstrap==3.3.7.1" \
    flask_sqlalchemy==3.1.1 \
    flask-migrate==4.0.7 \
    flask-login==0.6.3 \
    flask-wtf==1.2.1 \
    email_validator \
    matplotlib \
    python-Levenshtein \
    requests \
 && ln -sf /usr/local/bin/hug /usr/bin/hug \
 && cp -r /usr/lib/python3/dist-packages/nftables /usr/local/lib/python3.11/site-packages/nftables

VOLUME ["/opt/app/nftables-frontend/instance","/opt/app/nftables-frontend/static/img"]

ENTRYPOINT ["/usr/local/bin/gunicorn","-c","gunicorn.conf.py"]
