FROM alpine:latest

ARG ARCH
ARG OVERLAY_ARCH
ARG RCLONE_VERSION=1.65.0
ARG OVERLAY_VERSION=v2.2.0.3

WORKDIR /opt/autoscan

ENV CONFIG_DIR="/config" \
    PUID="1000" \
    PGID="1000" \
    UMASK="002" \
    S6_BEHAVIOUR_IF_STAGE2_FAILS=2 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/plex_autoscan:${PATH} \
    TZ=Europe/Brussels \
    AUTOSCAN_CONFIG=/config/config.json \
    AUTOSCAN_LOGFILE=/config/autoscan.log \
    AUTOSCAN_LOGLEVEL=INFO \
    AUTOSCAN_QUEUEFILE=/config/queue.db \
    AUTOSCAN_CACHEFILE=/config/cache.db

ARG RCLONE_URL="https://github.com/rclone/rclone/releases/download/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-linux-${ARCH}.zip"
ARG S6_URL="https://github.com/just-containers/s6-overlay/releases/download/${OVERLAY_VERSION}/s6-overlay-${OVERLAY_ARCH}-installer"

RUN wget -q -O rclone.zip $RCLONE_URL && \
    unzip rclone.zip && \
    mv rclone-*/rclone /bin/rclone && \
    chmod +x /bin/rclone && \
    rm -rf rclone.zip rclone-*

RUN wget -q $S6_URL -O /tmp/s6-overlay-${OVERLAY_ARCH}-installer && \
    chmod +x /tmp/s6-overlay-${OVERLAY_ARCH}-installer && \
    /tmp/s6-overlay-${OVERLAY_ARCH}-installer / && \
    rm /tmp/s6-overlay-${OVERLAY_ARCH}-installer

COPY . .

RUN apk add --no-cache --upgrade python3 git py3-pip py3-setuptools shadow bash docker-cli && \
    apk --no-cache --virtual=build-deps add gcc linux-headers musl-dev python3-dev && \
    pip install -U --no-cache-dir pip idna wheel --break-system-packages && \
    pip install -U --no-cache-dir pip -r requirements.txt --break-system-packages && \
    apk --purge del build-deps && \
    ln -s /opt/plex_autoscan/config /config

COPY /root /

RUN useradd -u 1000 -U -d "${CONFIG_DIR}" -s /bin/false autoscan && \
    usermod -G users autoscan

LABEL org.opencontainers.image.source = "https://github.com/NiNiyas/autoscan"
LABEL MAINTAINER="NiNiyas"
LABEL org.opencontainers.image.description="Autoscan is a python script that assists in the importing of Sonarr, Radarr, and Lidarr downloads into Plex and/or Jellyfin/Emby."
LABEL org.opencontainers.image.licenses="GNU General Public License v3.0"

VOLUME ["/config", "/plexDb"]

EXPOSE 3468/tcp

CMD ["python3", "scan.py" , "server"]
ENTRYPOINT ["/init"]
