#!/usr/bin/env bash
if [ "$(id -u)" -ne "0" ]; then
   echo "This script must be run as root" >&2
   exit 1
fi

if [ "$1" = 'enable' ]; then
    if [ -f /srv/easyrsa/pki/ca.crt ]; then
      cp /srv/easyrsa/pki/ca.crt /etc/nginx/client_certs_ca.crt
    else
      echo 'Error: No client CA certificate at /srv/easyrsa/pki/ca.crt'
    fi

    if [ -f /srv/haxfarm/xhq-certauth.nginx.site.conf ]; then
      cp /srv/haxfarm/xhq-certauth.nginx.site.conf /etc/nginx/sites-available/xhq-certauth
      rm /etc/nginx/sites-enabled/xhq
      ln -s /etc/nginx/sites-available/xhq-certauth /etc/nginx/sites-enabled/xhq
    else
      echo 'Error: Config file missing (/srv/haxfarm/xhq-certauth.nginx.site.conf)'
    fi

    if /usr/sbin/nginx -t; then
      systemctl restart nginx
    fi
elif [ "$1" = 'disable' ]; then
    rm /etc/nginx/sites-enabled/xhq
    ln -s /etc/nginx/sites-available/xhq /etc/nginx/sites-enabled/xhq

    if /usr/sbin/nginx -t; then
      systemctl restart nginx
    fi
else
    echo "Usage: $0 enable | disable"
fi

