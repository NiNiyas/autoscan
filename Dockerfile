FROM alpine:latest

ARG ARCH
ARG OVERLAY_ARCH
ARG RCLONE_VERSION=1.59.1
ARG OVERLAY_VERSION=v2.2.0.3

LABEL org.opencontainers.image.source = "https://github.com/NiNiyas/autoscan"

ARG RCLONE_URL="https://github.com/rclone/rclone/releases/download/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-linux-${ARCH}.zip"
ARG S6_URL="https://github.com/just-containers/s6-overlay/releases/download/${OVERLAY_VERSION}/s6-overlay-${OVERLAY_ARCH}-installer"

ENV TZ Europe/Brussels

WORKDIR /opt/autoscan

RUN apk add --no-cache --update tzdata tini python3 git py3-pip py3-setuptools logrotate shadow bash docker-cli && \
    pip3 install --upgrade pip idna wheel

COPY . .

RUN wget -q -O rclone.zip $RCLONE_URL && \
    unzip rclone.zip && \
    mv rclone-*/rclone /bin/rclone && \
    chmod +x /bin/rclone && \
    rm -rf rclone.zip rclone-*

RUN wget -q $S6_URL -O /tmp/s6-overlay-${OVERLAY_ARCH}-installer && \
    chmod +x /tmp/s6-overlay-${OVERLAY_ARCH}-installer && \
    /tmp/s6-overlay-${OVERLAY_ARCH}-installer / && \
    rm /tmp/s6-overlay-${OVERLAY_ARCH}-installer

RUN apk -U --no-cache --virtual .build-deps add gcc linux-headers musl-dev python3-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk -U --no-cache del .build-deps && \
    ln -s /opt/plex_autoscan/config /config

ENV DOCKER_CONFIG=/home/autoscan/docker_config.json \
    AUTOSCAN_CONFIG=/config/config.json \
    AUTOSCAN_LOGFILE=/config/autoscan.log \
    AUTOSCAN_LOGLEVEL=INFO \
    AUTOSCAN_QUEUEFILE=/config/queue.db \
    AUTOSCAN_CACHEFILE=/config/cache.db \
    PATH=/opt/plex_autoscan:${PATH}

RUN addgroup -S autoscan && adduser -S autoscan -G autoscan

VOLUME ["/config", "/plexDb"]

EXPOSE 3468/tcp

CMD ["python3", "scan.py" , "server"]
ENTRYPOINT ["/init"]
