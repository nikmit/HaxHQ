import re
import os
import time
import logging
import qrcode
import pyotp
import pprint
from markupsafe import escape
from inspect import currentframe, getframeinfo
from decimal import Decimal
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, session, request, flash, redirect, abort, url_for
from ua_parser import user_agent_parser
from werkzeug.security import check_password_hash
from xhq.util import db_getrow, db_getcol, db_do, randstring, send_email, get_engagement_id, logerror
from xhq.authorise_config import get_routes, admin_routes
import xhq.forms

logger = logging.getLogger(__name__)
logger.setLevel('INFO')
#logger.setLevel('DEBUG')

app = Flask(__name__)
app.config.from_object('def_settings')

def authenticate(token = None):
    logger.debug('authenitcating user')
    # get user by token or user/pass
    if token:
        # check token and login
        return verify(token)
    else:
        session['logged_in'] = False
        username = request.form['username']
        password = request.form['password']

        cert_username = None

        # if the CA ever switches to adding org info to the CN, this should still work
        cert_dn_list = request.headers.getlist("X-SSL-Client-S-Dn")
        if cert_dn_list:
            cert_dn_list = cert_dn_list[0].split(',')

            for dn in cert_dn_list:
                m = re.search('CN=(.+)$', dn)
                if m:
                    cert_username = m[1]
                    logger.info(cert_username)
        else:
            logger.debug('No X-SSL-Client-S-Dn header')

        if cert_username and cert_username != username:
            logger.error('Certificate username mismatch')
            flash('The client certificate used is not issued to the current user', 'error')
            return False

        #TODO another user data query is done at 678, the data could be passed on instead?
        qry = db_getrow('select id, nickname, email, pass, user_group, admin, customer_id, otp_secret, colour_mode, certfp, oldcertfp\
                         from users where email = %s', (username,))

        if not qry['success']:
            logger.error('Query failed')
            return False

        stored_user = qry['data']

        # ratelimit password auths (token auth not limited)
        if authrate():
            # if found, try to log them in
            if stored_user:
                if stored_user['pass']:
                    if check_password_hash(stored_user['pass'], password):
                        logger.info("Valid password for user " + username)
                        session['pass_checked'] = True
                        session['user_id'] = stored_user['id']
                        session['email'] = stored_user['email']
                        session['colour_mode'] = stored_user['colour_mode']
                        session['logged_in'] = False

                        qry = db_getrow('select mfa_required from customers where id = %s', (stored_user['customer_id'],))
                        if qry['success']:
                            if qry['data']:
                                mfa_required = qry['data']['mfa_required']
                                session['mfa_required'] = mfa_required
                                logger.debug('set mfa requirement for the session: ' + repr(mfa_required))
                            else:
                                logger.error('could not find customer')
                                flash('Invalid customer ID')
                                return False
                        else:
                            # fail closed
                            logger.error('failed to get configured mfa requirement, setting to required')
                            session['mfa_required'] = True

                        if stored_user['otp_secret']:
                            logger.debug('otp secret configured, adding to session')
                            session['otp_secret'] = stored_user['otp_secret']
                            session['mfa_enabled'] = True
                        else:
                            session['mfa_enabled'] = False
                            if mfa_required:
                                logger.info('mfa required but not yet set up')
                            else:
                                #mfa not required or enabled, log the user in
                                logger.info("Successful login for user " + username)
                                logger.info("colour mode: " + session['colour_mode'])
                                login(stored_user)
                    else:
                        logger.info("Bad password for user " + username)
                        session['email'] = stored_user['email']
                        store_log(authfail=True)
                else:
                    logger.info("No password stored for user " + username)
                    session['email'] = stored_user['email']
                    store_log(authfail=True)
            else:
                logger.info('Login attempt with unregistered username ignored')
        else:
            logger.info("Login ratelimit enforced for user " + username)
            session['email'] = stored_user['email']
            store_log(authfail=True)

    return session['logged_in']

def login_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if check_session():
            if authorise_access():
                return f(*args, **kwargs)
            else:
                abort(401)
        else:
            flash('Invalid session, please log in', 'error')
            return redirect(url_for('login'))

    return inner

def authorise_access(route=None):
    """gets the user type and checks they are allowed to access the requested URL"""
    #TODO: redirect user to page they have access to rather than showing a 401
    logger.debug('authorising access')
    user_id = session['user_id']
    qry = db_getcol('select user_group from users where id = %s', (user_id,))
    group_str = qry['data'][0] if qry['data'] else ''
    allowed_routes = set()
    for group in group_str.split(','):
        allowed_routes = allowed_routes | get_routes(group)

    if session['isadmin']:
        allowed_routes = allowed_routes | admin_routes

    #logger.debug(repr(allowed_routes_set))

    # if not related to a request, route is passed explicitly (e.g. to check stats/admin access)
    if route:
        result = route in allowed_routes
        logger.debug('checking access to ' + route + ': ' + str(result))
        return result

    # request.path is e.g. /reporting/all
    _parts = request.path.split('/')
    route = _parts[1]
    if route not in allowed_routes:
        logger.warning('route not allowed: ' + route)
        return False
    else:
        logger.debug('route autorised: /' + route)
        return True

def check_session():
    logger.debug('checking session')
    if 'useragent' in session and session['useragent']:
        logger.debug('Cookie found, user agent is: ' + session['useragent'])
    else:
        # if the first URL visited is one that requires auth, no session will exist
        logger.debug('no session detected, redirecting to login. If this loops, cookies might be disabled.')
        return False

    if 'logged_in' in session and session['logged_in']:
        if not ('email' in session and 'user_id' in session):
            logger.info('invalid session: no email and/or user id in session data')
            pp = pprint.PrettyPrinter(depth=4)
            logger.debug(pp.pprint(session))
            return False
        elif not (session['user_id'] and session['email']):
            logger.info('invalid session: null email and/or user_id values')
            pp = pprint.PrettyPrinter(depth=4)
            logger.debug(pp.pprint(session))
            return False
        elif not 'user_groups' in session or not session['user_groups']:
            logger.debug('user_groups not set for session')
            return False
    else:
        return False

    client_ip = request.headers.getlist("X-Forwarded-For")[0].split(', ')[-1]
    useragent = request.headers.get('User-Agent')
    user_id = session['user_id']
    email = session['email']

    logger.debug('checking stored sessions for ' + repr((email,user_id,client_ip,useragent)))
    # get the logged IP and browser from database (force session timeout after 8 hours)
    sql = '''select ip, useragent, start, expired
             from user_sessions
             where user_id = %s and user_id not in (select id from users where disabled is true)
               and authfail is false and finish is null
             order by start desc limit 1'''

    qry = db_getrow(sql, (user_id, ))
    logged_session = qry['data']
    #logger.debug(repr(logged_session))
    # compare with session data stored in database
    if logged_session:
        if logged_session['expired']:
            logger.debug('session expired')
            flash('Session expired, please log in again', 'error')
            return False
        elif logged_session['start']:
            now = datetime.now()
            hard_expire = logged_session['start'] + timedelta(hours=8)
            logger.debug('session start: ' + repr(logged_session['start']) + ' expiry: ' + repr(hard_expire))
            if hard_expire < now:
                flash('Session older than 8 hours, please log in again', 'error')
                logger.info('session expired')
                expire_sessions(user_id)
                add_session()
                return False

        if logged_session['ip'] == client_ip:
            if logged_session['useragent'] == useragent:
                logger.debug('session validated')
                if 'tokenused' in session and not session['tokenused']:
                    logger.debug('user accessed authenticated resource after token auth, deleting token')
                    session['tokenused'] = True
                    qry = db_do('update users set token = null, token_time = null where id = %s', (user_id,))
                    if not qry['success']:
                        logger.error('failed to delete auth token from database')

                return True
            else:
                logger.warn('session destroyed, browser changed for ' + email)
                logger.warn('{} --> {}'.format(logged_session['useragent'], useragent))
                flash('Client browser changed, please log in again', 'error')
        else:
            logger.warn('session destroyed, ip changed for {}'.format(email))
            logger.warn('{} --> {}'.format(logged_session['ip'], client_ip))
            flash('Client IP changed, please log in again', 'error')
    else:
        logger.debug('no valid session found for ' + email)

    session['logged_in'] = False
    expire_sessions(user_id)
    return False

# pre-creates session for cookie check
def add_session():
    session.clear()
    session['ip'] = request.headers.getlist("X-Forwarded-For")[0].split(', ')[-1]
    logger.debug('adding empty session for remote address ' + session['ip'])
    session['useragent'] = request.headers.get('User-Agent')
    session['user_id'] = None
    session['email'] = None
    session['nickname'] = None
    session['user_groups'] = None
    session['pass_checked'] = False
    session['otp_secret'] = None
    session['mfa_required'] = False
    session['tokenverified'] = False

    session['logged_in'] = False

def logout():
    if 'logged_in' in session and session['logged_in']:
        qry = db_do('update user_sessions set finish = now()\
                     where user_id = %s and finish is null and expired is false and authfail is false', (session['user_id'],))
        if qry['success']:
            logger.info('Logout success: ' + session['nickname'])
        else:
            logger.error('failed to store user logout event')
    else:
        logger.debug('already logged out')

    add_session()
    return True

def authrate(user_id = None):
    ip = request.headers.getlist("X-Forwarded-For")[0].split(', ')[-1]
    useragent = request.headers.get('User-Agent')
    # rate limiting window size in minutes
    ratelimit_window = 10
    # max attempts within window
    threshold = 3
    logger.debug('checking rate limits for request from ' + ip)

    if user_id:
        logger.debug('checking auth ratelimit by user_id only')
        qry = db_getcol("select authfail from user_sessions\
                         where user_id = %s and start > now() - interval '" + str(ratelimit_window) + " min'\
                         order by start desc", (user_id,))
        if qry['success']:
            if qry['data']:
                logdata = qry['data']
                failcount = 0
                for authfail in logdata:
                    if authfail:
                        failcount += 1
                    if failcount > threshold:
                        session.pop('_flashes', None)
                        flash('Too many failed authentication attempts, please wait for ' + str(ratelimit_window) + ' min and try again', 'error')
                        return False
            else:
                # if no logged sessions, nothing to ratelimit
                return True
        else:
            flash('Server error','error')
            logger.error('failed to get user sessions data')
            return False

    elif request.form and 'username' in request.form:
        user = request.form['username']

        # track attempts from a single ip against multiple users
        # as well as attempts from multiple ips against a single user
        #NOTE attempts against non-existant users are not logged and therefore ignored
        sql = '''select extract(epoch from start) as epoch, user_id, ip, authfail::int
                 from user_sessions where user_id = (select id from users where email = %s) or ip = %s
                 order by epoch desc
                 limit 10'''

        logger.debug('checking auth request rate for ' + ip + '/' + user)
        qry = db_do(sql, (user, ip))
        logdata = qry['data']

        if logdata:
            logger.debug('got request history')
            #logger.debug(repr(logdata))
            # check if last auth attempt was within the ratelimit window
            min_age = round(time.mktime(time.gmtime()) - ratelimit_window*60)
            # count events
            for marker in ['ip', 'user_id']:
                logger.debug('checking auth ratelimit by ' + marker)
                eventcount = 0
                for epoch, hist_uid, hist_ip, authfail in logdata:
                    logger.debug('checking logged entry from ' + str(epoch))
                    # stop checking on encountering successful auth or leaving ratelimit window
                    if round(epoch) < min_age:
                        logger.debug('reached an entry older than min_age, not looking at older events')
                        break

                    if authfail:
                        logger.debug('recent failed auth request seen at :' + str(epoch))
                        eventcount += 1

                if eventcount > threshold:
                    logger.warn('ratelimiting auth request from ' + ip + ' browser ' + useragent)
                    flash('Too many failed authentication attempts, please wait for ' + str(ratelimit_window) + ' min and try again', 'error')
                    return False
    else:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'auth request without username')
        return False

    logger.debug('ratelimiting check OK, for request from ' + ip + ' browser ' + useragent)
    return True

def expire_logged_sessions(user_id):
    qry = db_do('''update user_sessions set expired = true
                   where user_id = %s and authfail is false and finish is null and expired is false''', (user_id, ))
    if qry['success']:
        logger.debug('New login, forced expiry for all pre-existing open sessions: ' + str(user_id))
    else:
        logger.error('failed to expire old session')

def login(user):
    client_ip = request.headers.getlist("X-Forwarded-For")[0].split(', ')[-1]
    ua = request.headers.get('User-Agent')
    session['user_id'] = str(user['id'])
    session['email'] = user['email']
    session['isadmin'] = user['admin']
    session['nickname'] = escape(user['nickname'])
    session['customer_id'] = str(user['customer_id'])
    session['user_groups'] = user['user_group'].split(',')
    session['logged_in'] = True
    session['client_ip'] = client_ip
    session['useragent'] = ua
    session['has_stats'] = authorise_access('stats')

    expire_logged_sessions(user['id'])
    store_log(authfail=False)

    logger.debug('authenticated session created')

    cert_rem_data = request.headers.getlist("X-SSL-Client-Remain")
    if cert_rem_data:
        session['cert_remaining'] = cert_rem_data[0].strip('\\')
        logger.debug('Client certificate valid for another ' + str(session['cert_remaining']) + ' days')
        if int(session['cert_remaining']) < 15:
            flash('Your client certificate will expire in ' + str(session['cert_remaining']) + ' days. You can renew it from <a href='+ url_for('usersettings') +'>user settings</a>', 'error')
    else:
        logger.debug('failed to get client cert remaining days, client cert auth probably not enabled')

    # if oldcert exists and is not used for the current session, revoke it
    cert_fp_data = request.headers.getlist("X-SSL-Client-Fp")
    if cert_fp_data:
        used_cert_fp = cert_fp_data[0].strip('\\')
        logger.debug('user authenticated using certificate with fingerprint ' + used_cert_fp)
        if user['oldcertfp']:
            logger.info(user['email'] + ' client certificate was renewed recently')
            if used_cert_fp.lower() == user['certfp'].lower():
                logger.info(user['email'] + ' logged in using new certificate, revoking the old one')
                status = xhq.admin.revoke_renewed(user['email'])
                if status['success']:
                    logger.info('Successfuly revoked')
                    qry = db_do('update users set oldcertfp = null where id = %s', (user['id'],))
                    if qry['success']:
                        logger.debug('Old certificate info removed from database')
                        flash('Client certificate renewal complete: the old certificate was revoked', 'info')
            elif used_cert_fp.lower() == user['oldcertfp'].lower():
                logger.info(user['email'] + ' logged in using old certificate, abandon revoking it')
                flash('You are using an old client certificate. You can download your new certificate from <a href='+ url_for('usersettings') +'>user settings</a>', 'error')
                session['oldcert_used'] = True
        else:
            logger.debug('no oldcertfp record in db')
    else:
        logger.debug('failed to get client cert fingerprint, client cert auth probably not enabled')


    #logger.debug(repr(session.keys()))
    #logger.debug(repr(user))

## send email notification on successful login
#    os_str = None
#    browser_str = None
#    os = user_agent_parser.ParseOS(ua)
#    browser = user_agent_parser.ParseUserAgent(ua)
#    if os:
#        if 'family' in os and os['family']:
#            os_str = os['family']
#            if 'major' in os and os['major']:
#                os_str += ' ' + os['major']
#            logger.debug('parsed os as: ' + os_str)

#    if browser:
#        if 'family' in browser and browser['family']:
#            browser_str = browser['family']
#            if 'major' in browser and browser['major']:
#                browser_str += ' ' + browser['major']
#            logger.debug('parsed browser as: ' + browser_str)

#    msg = '''Successfull login to xhq!
#
#If this wasn't you please change your password as soon as possible.
#
#'''

#    if os_str and browser_str:
#        msg += '''
#Username: %s
#IP address: %s
#Browser: %s
#Operating System: %s
#
#''' % (email, client_ip, browser_str, os_str)
#    else:
#        msg += '''
#IP address: %s
#Browser: %s
#''' % (client_ip, ua)

#    send_email(email, 'Successful login to xhq', msg)

def store_log(session_end = False, authfail = False):
    # log session start and end events
    # log tokens sent 
    if 'user_id' in session:
        user_id = session['user_id']
    elif 'email' in session:
        logger.error('user_id missing from authenticated session')
        qry = db_getcol('select id from users where email = %s', (session['email'],))
        user_id = qry['data'][0] if qry['data'] else None
    else:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'cant store log without user id or email')
        return False

    if session_end:
        # on login pre-existing open sessions are expired so this should always close a single session
        qry = db_do('update user_sessions set finish = now() where user_id = %s and finish is null and expired is false', (user_id,))
        if qry['success']:
            rows = qry['data']
            logger.debug('closed ' + str(rows) + ' open session/s for user ' + str(user_id))
            return True
        else:
            logger.error('failed to store user session end in db')

    client_ip = request.headers.getlist("X-Forwarded-For")[0].split(', ')[-1]
    useragent = request.headers.get('User-Agent')

    if not authfail:
        # if failed auth has been passed (on password update) don't discover it here
        authfail = 'false' if session['logged_in'] else 'true'

    prm = (user_id, client_ip, useragent, authfail)
    sql = 'insert into user_sessions (user_id, ip, useragent, authfail) values (%s, %s, %s, %s)'

    qry = db_do(sql, prm)
    if qry['success']:
        logger.debug('stored authlog: ' + repr(prm))
        return True
    else:
        logger.error('failed to store log')
        return False

def expire_sessions(user_id):
    qry = db_do('''update user_sessions set expired = true
                   where authfail is false and finish is null and expired is false
                    and user_id = %s''', (user_id, ))
    if qry['success']:
        logger.debug('Expired open sessions for user ' + str(user_id))
    else:
        logger.debug('Failed to expire open sessions for user ' + str(user_id))

def reset_pass(user):
    status = {'success': False, 'error': None}
    qry = db_getrow('select id, nickname, email from users where email = %s', (user,))
    valid_user = None
    if qry['success']:
        valid_user = qry['data']
    else:
        status['error'] = 'System error, please contact support using the link at the bottom of the page'
        return status

    if valid_user:
        logger.debug('password reset requested by ' + user)
        user_id = valid_user['id']
        token = randstring(size=68)
        now = datetime.now()
        #time = now.strftime('%d/%m/%Y, %H:%M:%S')
        qry = db_do('update users set token = %s, token_time = %s where id = %s', (token, now, user_id))
        if qry['success']:
            logger.debug('password reset token stored for ' + user)
        else:
            status['error'] = 'System error, please contact using the link in the footer of the page'
            logger.error('Failed to store password reset token for ' + user)
            return status

        subject = 'HaxHQ password reset requested'
        login_url = request.url_root + 'checktoken?token=' + token
        message = '''Hi {},

Someone requested a password reset for your HaxHQ account. If this was you, please visit {} to set a new password.

If this wasn't you, you can ignore this email.

Regards,
HaxHQ'''

        status = send_email(valid_user['email'], subject, message.format(valid_user['nickname'], login_url))
        if status['success']:
            logger.debug('Password reset email sent to ' + valid_user['email'])
        else:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'Failed to send password reset email')
            logger.error(valid_user['email'])
            status['error'] = 'Failed to send password reset email, please contact support or use the CLI password reset feature'

    else:
        logger.info('bad user in password reset request: ' + user)
        status['success'] = True

    return status

def verify(token):
    '''checks token is valid for current user then deletes it
       runs login() to add session params
       no rate limiting for using tokens (should not be brute forceable)
       token validity 30 min'''
    token_expiry = 1800

    session['tokenverified'] = False
    logger.debug('checking token ' + token)
    sql = 'select id, email, nickname, extract(epoch from token_time)::int as token_time, user_group, admin, customer_id, otp_secret,\
                  colour_mode\
           from users where token = %s'
    qry = db_getrow(sql, (token, ))
    stored_user = qry['data']
    if stored_user:
        logger.debug('found token for: ' + stored_user['nickname'])
        now = int(time.time())
        if now - stored_user['token_time'] > token_expiry:
            qry = db_do('update users set token = null, token_time = null where id = %s', (stored_user['id'],))
            if qry['success']:
                logger.debug('expired token deleted')
            else:
                logger.error('failed to delete expired token')

            flash('Token expired, please use the password reset feature again to create a new one', 'error')
        else:
            logger.debug('token is valid, checking if mfa is needed')
            session['tokenverified'] = True
            session['tokenused'] = False
            session['email'] = stored_user['email']
            session['colour_mode'] = stored_user['colour_mode']
            if stored_user['otp_secret']:
                logger.debug('otp secret configured, adding to session')
                session['otp_secret'] = stored_user['otp_secret']
                session['mfa_enabled'] = True
            else:
                session['mfa_enabled'] = False
                qry = db_getcol('select mfa_required from customers where id = %s', (stored_user['customer_id'],))
                if qry['data']:
                    mfa_required = qry['data'][0]
                    if mfa_required:
                        logger.info('mfa required but not yet set up')
                        session['mfa_required'] = True
                    else:
                        #mfa not required or enabled, log the user in
                        logger.info("Successful login for user " + stored_user['email'])
                        login(stored_user)
                        return True
                else:
                    #fail closed
                    logger.error('failed to get customer mfa requirements')
                    flash('Server error, please contact support')
                    return False
    else:
        flash('Invalid token (tokens are single use).', 'error')
        logger.warning('token not found: ' + token)

    return False

def setup_mfa(save=False):
    user_email = session['email']
    qry  = db_getcol('select otp_secret from users where email = %s', (user_email,))
    if qry['data'] and qry['data'][0]:
        logger.debug('mfa already_enabled')
        return False

    if save:
        logger.debug('saving otp_secret for user ' + user_email)
        qry = db_do('update users set otp_secret = %s where email = %s', (session['otp_secret'], user_email))
        if qry['success']:
            session['mfa_enabled'] = True
            qry = db_getrow('select id, nickname, email, user_group, admin, customer_id from users where email = %s', (user_email,))
            user = qry['data']
            logger.debug('deleting qrcode image file at ' + app.config['QRCODE_FOLDER'] + session['qr_img'])
            os.remove(app.config['QRCODE_FOLDER'] + session['qr_img'])
            del session['qr_img']
            del session['otp_secret']
            return user
        else:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to save otp secret for user')
            logger.error('failed to save otp secret for user ' + user_email)
            return False
    else:
        result = {'subtitle': 'Login', 'user_groups': []}
        logger.info('setting up mfa for user ' + user_email)
        secret = pyotp.random_base32()
        otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user_email, issuer_name='HaxHQ')
        imgfile = 'qr_' + str(session['user_id']) + '.png'
        img = qrcode.make(otp_uri)
        img.save(app.config['QRCODE_FOLDER'] + imgfile)
        session['otp_secret'] = secret
        session['qr_img'] = imgfile
        result = result | {'img': imgfile, 'secret': secret}

        return result

def check_2fa():
    logger.info('checking 2fa')
    otp_code = request.form['otp_code']
    secret = session['otp_secret']
    if not secret:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'otp secret is undefined: ' + repr(session))
        return False

    totp = pyotp.TOTP(secret)
    user = None
    if totp.verify(otp_code):
        logging.info('2fa verified')
        qry = db_getrow('select id, nickname, email, user_group, admin, customer_id, certfp, oldcertfp, colour_mode\
                         from users where email = %s', (session['email'],))
        user = qry['data']
    else:
        logger.debug('2fa code incorrect')

    return user



