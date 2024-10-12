#!/usr/bin/env bash
if [ "$(id -u)" -ne "0" ]; then
   echo "This script must be run as root" >&2
   exit 1
fi
### CONFIGURATION ###
#LICENSES=3
DOMAIN='test.com'
#GIT_USER='test'
#GIT_PASS='c53H86QxiM0ganhbTr9YbjGxGLE4uGq3mnjl1R5CvJ'
BUSINESS_NAME='Awesome Hackers LTD'
BUSINESS_EMAIL='ceo@test.com'
HAXHQ_USER_NICKNAME='hacker1'
HAXHQ_USER_JOBTITLE='Senior Pen Tester'
HAXHQ_USER_EMAIL='hacker1@test.com'
INSTALLDIR='/opt/haxhq.com/'
DBNAME='haxhq'
DBUSER='flask'
REPO='haxhq'
OS_ADMIN_USER='operations'
CADIR='/opt/easyrsa'
HAXHQ_RUNAS='haxhq'
### END CONFIGURATION ###
CA_KEY=`openssl rand -base64 42`
CSRF_KEY=`openssl rand -base64 42`
DBPASS=`openssl rand -base64 32`
WORDS=`shuf -n3 /usr/share/dict/words | tr '\n' ' '`
OS_ADMIN_PASS="${WORDS::-1}"  # remove the trailing space!
HPASS=`openssl rand -base64 32`
/usr/sbin/useradd --shell /bin/false "$HAXHQ_RUNAS"
/usr/bin/echo "$HAXHQ_RUNAS:$HPASS" | chpasswd
/usr/sbin/usermod -L "$HAXHQ_RUNAS"
/usr/sbin/useradd -m --shell /bin/bash $OS_ADMIN_USER
/usr/bin/echo "$OS_ADMIN_USER:$OS_ADMIN_PASS" | chpasswd
/usr/sbin/usermod -a -G sudo "$OS_ADMIN_USER"

#XXX allow the haxhq user to reload nginx configuration.
#    Required to enable config changes (below) and server/client certificate updates
echo "$HAXHQ_RUNAS ALL=(root) NOPASSWD: /usr/sbin/nginx -s reload" > /etc/sudoers.d/"$HAXHQ_RUNAS"
#XXX allow the haxhq user to switch between available nginx sites.
#    Required to enable toggling of client certificate authentication from the web interface.
echo "$HAXHQ_RUNAS ALL=(root) NOPASSWD: /usr/bin/ln -s -f /etc/nginx/sites-available/haxhq /etc/nginx/sites-enabled/haxhq" >> /etc/sudoers.d/"$HAXHQ_RUNAS"
echo "$HAXHQ_RUNAS ALL=(root) NOPASSWD: /usr/bin/ln -s -f /etc/nginx/sites-available/haxhq-certauth /etc/nginx/sites-enabled/haxhq" >> /etc/sudoers.d/"$HAXHQ_RUNAS"
chmod 0440 /etc/sudoers.d/"$HAXHQ_RUNAS"
#apt -y install vim sudo tcpdump iptables-persistent ntp net-tools nullmailer aptitude libmime-lite-perl man-db manpages-posix curl wget
apt -y install git nginx postgresql python3-venv memcached sudo aptitude
## setup CA
if git clone -b haxhq https://"$GIT_USER":"$GIT_PASS"@updates.haxhq.com:5885/easyrsa "$CADIR"; then
  echo 'Repository cloned'
else
    echo 'Failed to clone haxhq repository'
    exit 1
fi
# setup HaxHQ
if git clone https://"$GIT_USER":"$GIT_PASS"@updates.haxhq.com:5885/"$REPO" "$INSTALLDIR"; then
    echo 'Repository cloned'
else
    echo 'Failed to clone haxhq repository'
    exit 1
fi
cd "$INSTALLDIR"/haxhq
mkdir logs xml report_templates generated_reports qrcode
chmod 775 logs xml report_templates generated_reports haxhq qrcode
#/usr/sbin/usermod -a -G $OS_ADMIN_USER haxhq
cd "$INSTALLDIR"/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
echo "import os
#DEBUG = True
SECRET_KEY = os.urandom(42)
WTF_CSRF_SECRET_KEY = '$CSRF_KEY'
#WTF_CSRF_TIME_LIMIT = None
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE='Strict'
SESSION_COOKIE_NAME = 'haxhq_session'
SESSION_TYPE = 'filesystem'
SESSION_PERMANENT = True
UPLOAD_FOLDER = '../xml'
REPORT_FOLDER = '../generated_reports'
PENTEST_TEMPLATE = 'pentest_report_template.docx'
AUDIT_TEMPLATE = 'audit_report_template.docx'
VULNSCAN_TEMPLATE = 'vulnscan_report_template.docx'
FAVICON_FOLDER = 'static/favicon'
QRCODE_FOLDER = '../qrcode/'
ALLOWED_EXTENSIONS = {'xml', 'nessus', 'html', 'txt'} 
DB_NAME = '$DBNAME'
DB_USER = '$DBUSER'
DB_PASS = '$DBPASS'
CA_KEY = '$CA_KEY'
CADIR = '$CADIR'
SMTP_SERVER = 'smtp.haxhq.com'
SENDER_DOMAIN = '$DOMAIN'
# requires SSL connection.
# STARTTLS and plaintext are insecure but support can be added if security is provided in alternative ways
SMTP_PORT = '587'
#SMTP_USER = ''
#SMTP_PASS = ''
SHOWLOGS=True
ORG_NAME = '$BUSINESS_NAME'
GIT_USER='$GIT_USER'
GIT_PASS='$GIT_PASS'" > haxhq/haxhq/def_settings.py
sudo -u postgres psql -c "create role $DBUSER with password '$DBPASS' login;"
sudo -u postgres psql -c "create database $DBNAME with owner $DBUSER;"
sudo -u postgres psql -c "alter database $DBNAME set datestyle to 'ISO, DMY';"
cd "$INSTALLDIR"/haxhq/haxhq
if flask initdb; then
# ADD INITIAL USER
    sudo -u postgres psql -d "$DBNAME" -c "insert into customers (contact_email, business_name, licenses) values ('$BUSINESS_NAME', '$BUSINESS_EMAIL', $LICENSES)"
    sudo -u postgres psql -d "$DBNAME" -c "insert into users (nickname, email, user_type, user_group, customer_id, admin) values ('$HAXHQ_USER_NICKNAME', '$HAXHQ_USER_EMAIL', '$HAXHQ_USER_JOBTITLE', 'hackers', 1, true)"
else
    echo "failed to initialise database"
    exit 1
fi
if flask init_ca; then
    echo 'Initialised integrated root CA'
else
    echo "failed to initialise CA"
    exit 1
fi
cp "$CADIR"/pki/ca.crt "$INSTALLDIR"/haxhq/haxhq/static/ca.crt
mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.orig
cp "$INSTALLDIR"/nginx.conf /etc/nginx/nginx.conf
echo "map \$http_upgrade \$connection_upgrade {
    default upgrade;
    '' close;
}

upstream haxhq {
    server unix:$INSTALLDIR/haxhq/haxhq/app.sock;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name haxhq.$DOMAIN;

    ssl_certificate $CADIR/pki/issued/haxhq.$DOMAIN.crt;
    ssl_certificate_key $CADIR/pki/private/haxhq.$DOMAIN.key;
    ssl_dhparam $CADIR/pki/dh.pem;

    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection \"1; mode=block\";
    add_header Content-Security-Policy \"script-src 'self' object-src 'self' frame-ancestors 'none'\";
    add_header Strict-Transport-Security \"max-age=31536000; includeSubdomains; preload\";" |tee /etc/nginx/sites-available/haxhq-certauth /etc/nginx/sites-available/haxhq > /dev/null

echo "
    # client certificate
    ssl_client_certificate $CADIR/pki/ca.crt;
    # make verification optional, so we can display a 403 message to those
    # who fail authentication
    ssl_verify_client optional;
    ssl_crl $CADIR/pki/crl.pem;

    error_page  403  /client_certificate_required.html;
    location = /client_certificate_required.html {
        root /opt/haxhq.com/html;
        internal;
    }

    location / {
        # if the client-side certificate failed to authenticate, show a 403 message to the client
        if (\$ssl_client_verify != SUCCESS) {
            error_page  403  /static/client_certificate_required.html;
            return 403;
        }

        include proxy_params;
        proxy_pass http://haxhq;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header X-SSL-Client-S-Dn \$ssl_client_s_dn;
        proxy_set_header X-SSL-Client-Remain \$ssl_client_v_remain;
        proxy_set_header X-SSL-Client-Fp \$ssl_client_fingerprint;
    }
}" >> /etc/nginx/sites-available/haxhq-certauth

echo "
    location / {
        include proxy_params;
        proxy_pass http://haxhq;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
    }
}" >> /etc/nginx/sites-available/haxhq

ln -s /etc/nginx/sites-available/haxhq /etc/nginx/sites-enabled/haxhq

echo "$INSTALLDIR/haxhq/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    su $HAXHQ_RUNAS $HAXHQ_RUNAS
    create 0660 $HAXHQ_RUNAS $HAXHQ_RUNAS
    postrotate
    /bin/systemctl restart haxhq.service
    endscript
}" > /etc/logrotate.d/haxhq.logrotate

echo "[Unit]
#  specifies metadata and dependenciesDescription=Gunicorn instance to serve myproject
After=network.target
# tells the init system to only start this after the networking target has been reached# We will give our regular user account ownership of the process since it owns all of the relevant files
[Service]
# Service specify the user and group under which our process will run.
User=$HAXHQ_RUNAS
# give group ownership to the www-data group so that Nginx can communicate easily with the Gunicorn processes.
Group=$HAXHQ_RUNAS
# We'll then map out the working directory and set the PATH environmental variable so that the init system knows where our the executables for the process are located (within our virtual environment).
WorkingDirectory=$INSTALLDIR/haxhq/haxhq
Environment="PATH=$INSTALLDIR/venv/bin"
StandardError=append:$INSTALLDIR/haxhq/logs/haxhq.log
# We'll then specify the commanded to start the service
ExecStart=$INSTALLDIR/venv/bin/gunicorn --workers 3 --timeout 360 --bind unix:app.sock -m 011 wsgi:app
# This will tell systemd what to link this service to if we enable it to start at boot. We want this service to start when the regular multi-user system is up and running:
[Install]
WantedBy=multi-user.target" > /etc/systemd/system/haxhq.service
#chown -R $OS_ADMIN_USER:haxhq $INSTALLDIR/*
echo "#!/bin/bash
source $INSTALLDIR/venv/bin/activate
cd $INSTALLDIR/haxhq/haxhq

$INSTALLDIR/venv/bin/python haxhqcli.py \$@

if [ "$(id -u)" -eq "0" ]; then
  /usr/bin/chown -R $HAXHQ_RUNAS:$HAXHQ_RUNAS $CADIR/pki
  /usr/bin/chmod +rx $CADIR/pki
  /usr/bin/chmod +r $CADIR/pki/ca.crt
fi
" > /usr/local/bin/haxhqcli

chmod 755 /usr/local/bin/haxhqcli
IP=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'`
echo "
To finalise your setup:
1) update the operations user passwd - if you are logged in as operations just run 'passwd'
2) update the root password with e.g. 'sudo -u root passwd'
3) check network connectivity with 'haxhqcli check_connectivity'
4) check the system time using 'date'.
   If it is not accurate, update it with 'sudo systemctl stop ntpd && sudo ntpd -gq && sudo systemctl start ntpd'
5) re-initialise the certificate authority so a new private key is generated for the root certificate: 'sudo -u haxhq haxhqcli init_ca'
6) download the generated root CA certificate from https://$IP/static/ca.crt and
   install it in your browser as a trusted root CA. This will remove certificate warnings and help protect against MitM attacks.
7) set the password for the initial HaxHQ admin user: 'sudo -u haxhq haxhqcli update_pass $HAXHQ_USER_EMAIL'
8) login at https://$IP as $HAXHQ_USER_EMAIL with the password you just set

The above steps should only take a couple of minutes. Please do email support@haxhq.com if you need help at any stage, we will be happy to help.

Once you are logged in to the web interface, you can add further users as needed (user menu -> Administration)

While you are on the Administration page you may also want to download the default report template and apply your branding,
then upload it again. If you prefer, email support@haxhq.com with your current template and we will create a HaxHQ compatible version of it.
" > /home/$OS_ADMIN_USER/HaxHQ_readme.txt

echo "# m h  dom mon dow   command
0 5 01 * * haxhq /usr/local/bin/haxhqcli renew_server_cert" > /etc/cron.d/haxhq

chown -R "$HAXHQ_RUNAS":"$HAXHQ_RUNAS" "$INSTALLDIR" "$CADIR"
systemctl daemon-reload
systemctl enable haxhq
systemctl start haxhq
systemctl restart nginx
systemctl stop ntpd
/usr/sbin/ntpd -gq
systemctl start ntpd

echo "admin user: $OS_ADMIN_USER"
echo "admin pass: $OS_ADMIN_PASS"
