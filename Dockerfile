FROM alpine:3.7

MAINTAINER Christophe Tafani-Dereeper <christophe@tafani-dereeper.me>

ADD . /app
WORKDIR /app

RUN apk add --no-cache --virtual persistent python3 nss && \
    pip3 install -r requirements.txt

ENTRYPOINT ["python3", "/app/firepwned.py", "--profile-path", "/profile"]