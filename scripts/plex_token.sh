#!/bin/sh -e
#########################################################################
# Title:         Retrieve Plex Token                                    #
# Author(s):     Werner Beroux (https://github.com/wernight)            #
# URL:           https://github.com/wernight/docker-plex-media-server   #
# Description:   Prompts for Plex login and prints Plex access token.   #
#########################################################################
#                           MIT License                                 #
#########################################################################

if [ -z "$PLEX_LOGIN" ] || [ -z "$PLEX_PASSWORD" ]; then
  PLEX_LOGIN=$1
  PLEX_PASSWORD=$2
fi

while [ -z "$PLEX_LOGIN" ]; do
  echo >&2 -n 'Your Plex login (e-mail or username): '
  read PLEX_LOGIN
done

while [ -z "$PLEX_PASSWORD" ]; do
  echo >&2 -n 'Your Plex password: '
  read PLEX_PASSWORD
done

echo >&2 'Retrieving a X-Plex-Token using Plex login/password...'

curl -qu "${PLEX_LOGIN}":"${PLEX_PASSWORD}" 'https://plex.tv/users/sign_in.xml' \
-X POST -H 'X-Plex-Device-Name: PlexMediaServer' \
-H 'X-Plex-Provides: server' \
-H 'X-Plex-Version: 0.9' \
-H 'X-Plex-Platform-Version: 0.9' \
-H 'X-Plex-Platform: xcid' \
-H 'X-Plex-Product: Plex Media Server'\
-H 'X-Plex-Device: Linux'\
-H 'X-Plex-Client-Identifier: XXXX' --compressed >/tmp/plex_sign_in
X_PLEX_TOKEN=$(sed -n 's/.*<authentication-token>\(.*\)<\/authentication-token>.*/\1/p' /tmp/plex_sign_in)
if [ -z "$X_PLEX_TOKEN" ]; then
  cat /tmp/plex_sign_in
  rm -f /tmp/plex_sign_in
  echo >&2 'Failed to retrieve the X-Plex-Token.'
  exit 1
fi
rm -f /tmp/plex_sign_in

echo >&2 "Your X_PLEX_TOKEN:"

echo $X_PLEX_TOKEN
