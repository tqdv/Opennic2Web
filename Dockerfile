FROM python:3.6-alpine

LABEL maintainer="Tilwa Qendov"
EXPOSE 8080 8443

WORKDIR /app
COPY requirements.txt ./

RUN apk add --no-cache --virtual .build-deps gcc musl-dev \
    && pip install --no-cache-dir -r requirements.txt     \
    && apk del .build-deps gcc musl-dev

# cf .dockerignore
COPY . .

CMD [ "python", "./o2w.py" ]