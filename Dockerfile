FROM alpine:latest

ARG OVERLAY_ARCH
ARG OVERLAY_VERSION=3.2.0.2

WORKDIR /usr/src/app

COPY . .

ENV CONFIG_DIR="/config" \
    PUID="1000" \
    PGID="1000" \
    UMASK="002" \
    S6_BEHAVIOUR_IF_STAGE2_FAILS=2 \
    PYTHONUNBUFFERED=1 \
    TZ=Europe/Brussels \
    AUTOSCAN_CONFIG=/config/config.json \
    AUTOSCAN_LOGFILE=/config/autoscan.log \
    AUTOSCAN_LOGLEVEL=INFO \
    AUTOSCAN_QUEUEFILE=/config/queue.db \
    AUTOSCAN_CACHEFILE=/config/cache.db \
    AUTOSCAN_COMMAND=server

RUN apk update && apk add --no-cache python3 py3-pip shadow bash docker-cli findutils inotify-tools && \
    apk add --no-cache --virtual=build-deps gcc linux-headers musl-dev python3-dev curl wget xz unzip git

RUN curl https://rclone.org/install.sh | bash

RUN curl -fsSL https://github.com/just-containers/s6-overlay/releases/download/v${OVERLAY_VERSION}/s6-overlay-noarch.tar.xz | tar Jpxf - -C / && \
    curl -fsSL https://github.com/just-containers/s6-overlay/releases/download/v${OVERLAY_VERSION}/s6-overlay-${OVERLAY_ARCH}.tar.xz | tar Jpxf - -C / && \
    curl -fsSL https://github.com/just-containers/s6-overlay/releases/download/v${OVERLAY_VERSION}/s6-overlay-symlinks-noarch.tar.xz  | tar Jpxf - -C / && \
    curl -fsSL https://github.com/just-containers/s6-overlay/releases/download/v${OVERLAY_VERSION}/s6-overlay-symlinks-arch.tar.xz | tar Jpxf - -C /

RUN pip install --no-cache-dir -r requirements.txt --break-system-packages && \
    apk --purge del build-deps

COPY /root /

RUN useradd -u 1000 -U -d "${CONFIG_DIR}" -s /bin/false autoscan && \
    usermod -G users autoscan

LABEL org.opencontainers.image.source = "https://github.com/NiNiyas/autoscan"
LABEL MAINTAINER="NiNiyas"
LABEL org.opencontainers.image.description="Autoscan is a python script that assists in the importing of Sonarr, Radarr, and Lidarr downloads into Plex and/or Jellyfin/Emby."
LABEL org.opencontainers.image.licenses="GNU General Public License v3.0"

VOLUME ["/config", "/plexDb"]

EXPOSE 3468/tcp

ENTRYPOINT ["/init"]
