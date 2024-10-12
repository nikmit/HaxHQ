import re
import os
import sys
import json
import time
import socket
import pexpect
import logging
import requests
import subprocess
import dns.resolver
from PIL import Image
from datetime import date, datetime, timedelta
from markupsafe import escape
from inspect import currentframe, getframeinfo
from flask import Flask, request, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from xhq.auth import authorise_access, store_log, authrate, logout, reset_pass
from xhq.engagement import create_dummy
from xhq.util import get_db, db_getrow, db_getcol, db_getdict, db_do, get_pg_update_sql, get_pg_insert_sql, logerror, randstring, send_email, resolve, email_enabled

logger = logging.getLogger(__name__)
logger.setLevel('INFO')
logger.setLevel('DEBUG')

def get_vars(page):
    '''Gets standards vars for the admin and usersettings pages'''
    res = {'page': page, 'user': session['nickname'], 'user_groups': session['user_groups'], 'isadmin': session['isadmin'],
           'subtitle': 'Administration', 'has_stats': session['has_stats'], 'mfa_enabled': session['mfa_enabled'],
           'mfa_required': session['mfa_required'], 'email_enabled': email_enabled()}#, 'updates_pending': get_updates()}

    # used to trigger a flash if the cert is nearing expiry
    if 'cert_remaining' in session:
        res['cert_remaining'] = session['cert_remaining']

    app = Flask(__name__)
    app.config.from_object('def_settings')
    if 'CERT_AUTH_ENABLED' in app.config and not app.config['CERT_AUTH_ENABLED']:
        res['certauthenabled']=False
    else:
        res['certauthenabled']=True

    # used in usersettings to determine action issue|renew|download
    # used in administration to check if the current user has a cert issued before enabling client cert auth
    qry = db_getrow('select certfp, oldcertfp, certexp from users where id = %s', (session['user_id'],))
    if qry['data']:
        res = res | qry['data']
    else:
        logger.error('Query failed')

    if page == 'admin':
        check = has_free_license()
        if check['success']:
            res['has_free_license'] = check['has_free_license']
        else:
            res['has_free_license'] = False
            flash('Could not check purchased licenses, please contact support')

        res['hidden_labels'] = ['CSRF Token', 'Save', 'Download', 'Update']
        qry = db_getdict('select id, email, user_group as group, admin, disabled, certfp from users where customer_id = %s order by id',
                                  (session['customer_id'],))
        res['users'] = qry['data']

        qry = db_getrow('select mfa_required from customers where id = %s', (session['customer_id'],))
        if qry['success']:
            res['mfa_required'] = qry['data']['mfa_required']
        else:
            res['mfa_required'] = False
            flash('Database query error, please contact support', 'error')

        status = get_login_logo()
        if status['success']:
            res = res | status['data']

    return res

def getuser(user_id):
    '''Returns stored data about a given user id for the admin edit user feature'''
    qry = db_getrow('select id as user_id, email, name, surname, nickname, phone, user_type,\
                            user_group as group, admin, disabled\
                     from users where customer_id = %s and id = %s',
                                  (session['customer_id'], user_id))
    return qry['data']

def updateuser():
    '''Update user settings as available to non admin users. Returns a boolean.'''
    user_id = session['user_id']
    form = request.form
    if 'nickname' in form:
        qry = db_do('update users set nickname = %s where id = %s', (form['nickname'], user_id))
        if qry['success']:
            session['nickname'] = form['nickname']
            return True
        else:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to update nickname for user ' + str(user_id))
            flash('Error updating nickname', 'error')

    if 'password' in form:
        # update an existing password
        current_pass = form['password']
        new_pass = form['password1'] if form['password1'] == form['password2'] else None

        if new_pass:
            qry = db_getcol('select pass from users where id = %s', (user_id,))
            if qry ['success']:
                stored_pass = qry['data'][0]
                if check_password_hash(stored_pass, current_pass):
                    status = update_pass(new_pass, user_id=user_id)
                    if status['success']:
                        logger.info('Updated password for user_id ' + str(user_id))
                        flash('Password updated', 'info')
                        return True
                    else:
                        logger.error(status['error'])
                        flash(status['error'], 'error')
                else:
                    error = 'Existing password mismatch, please try again'
                    flash(error, 'error')
                    logger.info(error)
                    store_log(authfail=True)
                    if not authrate(user_id = user_id):
                        logger.warning('user hit ratelimit when attempting to change password, logging them out')
                        flash('Authentication rate limit hit, please wait for a while before trying again', 'error')
                        logout()
        else:
            logger.debug('Passwords dont match, not updating')
            flash("The passwords didn't match, please try again", 'error')

    elif 'password1' in form:
        if session['tokenverified']:
            if form['password1'] == form['password2']:
                status = update_pass(form['password1'], user_id=user_id)
                if status['success']:
                    flash('Password updated', 'info')
                    session['tokenverified'] = False
                    return True
                else:
                    logger.error(status['error'])
                    flash(status['error'], 'error')
            else:
                logger.debug('Passwords dont match, not updating')
                flash("The passwords didn't match, please try again", 'error')
        else:
            logger.warning('attempt to update pass without verifying existing pass')
    else:
        logger.warning('bad data in save password form - no password or password1 submitted')

    return False

def update_pass(password, user_id=None, email=None):
    result = {'success': False, 'error': None}
    filters = []
    prm = []

    identifier = email if email else user_id
    if not identifier:
        result['error'] = 'Neither user_id nor email provided, cannot update password'
        logger.error(result['error'])
        return result

    if email:
        filters.append('email = %s')
        prm.append(email)

    if user_id:
        filters.append('id = %s')
        prm.append(user_id)

    filterstr = ' and '.join(filters)
    # check the user exists
    qry = db_getcol('select id from users where ' + filterstr, tuple(prm))
    if qry['success']:
        if qry['data']:
            logger.debug('User exists')
        else:
            result['error'] = 'Failed to update password: user '+ identifier +' not found'
            logger.error(result['error'])
            return result
    else:
        result['error'] = 'Failed to update password: query error'
        logger.error(result['error'])
        return result

    phash = generate_password_hash(password)
    # if updating through cli, assume single customer
    customer_id = session['customer_id'] if session and 'customer_id' in session and session['customer_id'] else '1'
    sql = 'update users set pass = %s where customer_id = %s'
    prm = [phash, customer_id]

    qry = db_do(sql, tuple(prm))
    if qry['success']:
        who = 'user_id: ' + str(user_id) if user_id else 'email: ' + email
        logger.info('Set password for ' + who + ', customer_id: ' + str(customer_id))
        result['success'] = True
    else:
        result['error'] = 'Failed to update password: query error'
        logger.error(result['error'])

    return result

def register():
    '''Registers a demo user as a customer with same email'''
    result = {'success': False, 'error': None}
    data = request.form
    app = Flask(__name__)
    app.config.from_object('def_settings')
    apikey = app.config['HAXHQ_KEY']

    if 'haxhq_key' in data and data['haxhq_key'] == apikey:
        logger.info('successfully authenticated register api call')
    else:
        logger.debug('ignoring api access attempt with bad or missing api key')
        logger.debug(repr(data))
        return abort(401)

    # check if a user is already registered with this email
    qry = db_getcol('select customer_id from users where email = %s', (data['email'],))
    if qry['success']:
        if qry['data']:
            logger.debug('sending password reset email to existing user: {}'.format(data['email']))
            status = reset_pass(data['email'])
            result = result | status
            result['customer_id'] = qry['data'][0]
            return result
        else:
            # normally a trial user's email would also be the customer email
            # check for fringe cases where user doesn't exist but a customer with that email does
            qry = db_getcol('select id from customers where contact_email = %s', (data['email'],))
            if qry['success']:
                if qry['data']:
                    logger.debug('found email registered as customer contact_email: {}'.format(data['email']))
                    result['customer_id'] = qry['data'][0]
            else:
                logger.error('query failed')
    else:
        logger.error('query failed')

    conn = get_db()
    curs = conn.cursor()
    if not 'customer_id' in result:
        logger.debug('no existing customer id found, creating a new customer')
        try:
            curs.execute("insert into customers (business_name, contact_email, mfa_required, licenses)\
                                         values (%s, %s, false, 10) returning id",
                                            (data['email'], data['email']))
            result['customer_id'] = curs.fetchone()[0]
        except Exception as e:
            logger.error(e.pgerror)
            result['error'] = 'Error saving customer entry'
            logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
            conn.close()
            return result

    if 'customer_id' in result and result['customer_id']:
        token = randstring(size=68)
        logger.info('demo customer created with id {}'.format(result['customer_id']))
        sql = "insert into users (nickname, email, name, surname, phone, token, token_time, user_type, user_group, admin, customer_id)\
                          values (%s, %s, 'Demo', 'User', '0123 456 789', %s, now(), 'Demo tester', 'hackers', true, %s) returning id"
        try:
            curs.execute(sql, (data['nickname'], data['email'], token, result['customer_id']))
            user_id = curs.fetchone()[0]
            conn.commit()
            conn.close()
            result['success'] = True
        except Exception as e:
            user_id = None
            logger.error(e.pgerror)
            result['error'] = 'Error saving new user at demo instance'
            logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
            conn.rollback()
            conn.close()
            return result

        if user_id:
            logger.info('demo user created with id {}'.format(user_id))
            message = 'A user just registered: ' + data['nickname'] + ' / ' + data['email']
            send_email('nik@haxhq.com', 'User registered: ' + data['email'], message)

            status = send_welcome(data['email'], data['nickname'], token)

            if status['success']:
                logger.debug('welcome email with login link successfully sent, user registered')
            else:
                logger.warning('failed to send welcome email with login link to newly registered user')
                logger.warn(status['error'])
                result['error'] = 'Failed to send welcome email to {}'.format(data['email'])

            logger.debug('creating a default dummy engagement')
            create_dummy('pentest', user_id=user_id)
            logger.debug('dummy engagement created')

        else:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to create demo user')
            logger.error('failed to create demo user')
    else:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to create demo customer')
        logger.error('failed to create demo customer')

    return result

def send_welcome(email, nickname, token, demo = True):
    demo_subject = 'Thank you for trying HaxHQ!'
    demo_message = '''Hi {nickname} ,

Thank you for trying HaxHQ! You can log in here: {login_link}

If you have any questions or comments, please do use the 'Contact support' link in the footer of every page.
We would love to help you make the most of the service; if you would like a guided tour and a chat about features please reply to this email with some suggested time slots. Our local time is GMT (EST +4, PST +7, AEDT -11).

Thanks,
HaxHQ team'''

    login_link = request.url_root + 'checktoken?token=' + token

    message = demo_message.format(nickname = escape(nickname), login_link = login_link)

    status = send_email(email, demo_subject, message)

    return status

def disable_2fa():
    if session['mfa_required']:
        logger.info('refusing to disable 2fa as it is required by customer')
        flash('2FA cannot be disabled here, as it is required by the subscription holder', 'error')
        return False

    user_id = session['user_id']
    qry = db_do('update users set otp_secret = null where id = %s', (user_id,))
    if qry['success']:
        logger.info('disabled 2fa for user id ' + str(user_id))
        session['mfa_enabled'] = False
        return True
    else:
        flash('Error disabling 2FA', 'error')
        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to disable 2FA for user id ' + str(user_id))
        return False

def toggle_colour_mode():
    new_mode = 'dark' if 'colour_mode' in session and session['colour_mode'] == 'light' else 'light'

    qry = db_do("update users set colour_mode = %s where id = %s", (new_mode, session['user_id']))
    if qry['success']:
        session['colour_mode'] = new_mode
    else:
        logger.error('failed to toggle colour scheme ' + new_mode)
        flash('Error enabling dark mode', 'error')

    return True

def set_template(filename, template_type, customer_id):
    if template_type in ['pentest', 'vulnscan', 'audit']:
        template_type = template_type + '_template'
        qry = db_do('update customers set ' + template_type + ' = %s where id = %s', (filename, customer_id))
        if qry['success']:
            logger.info(template_type + ' updated')
            result = True
        else:
            flash('failed to update ' + template_type + '. If this is a persistent error, please contact support.')
            result = False
    else:
        logger.info('bad template type: ' + repr(template_type))
        flash('Please select a template type')
        result = False

    return result

def get_template(template_type, template_version, customer_id):
    if template_type in ['pentest', 'vulnscan', 'audit']:
        template_type = template_type + '_template'
        if template_version == 'default':
            app = Flask(__name__)
            app.config.from_object('def_settings')
            filename = app.config[template_type.upper()]
        else:
            qry = db_getcol('select ' + template_type + ' from customers where id = %s', (customer_id,))
            if qry['data']:
                filename = qry['data'][0]
            else:
                logger.debug('No custom template configured, returning default template')
                app = Flask(__name__)
                app.config.from_object('def_settings')
                filename = app.config[template_type.upper()]

        logger.debug('version: ' + template_version + ', filename: ' + filename)
        return filename
    else:
        logger.info('bad template type passed: ' + str(template_type))
        flash('unrecognised template type, please try again', 'error')

        return None

def toggle_subscriber_mfa(customer_id):
    qry = db_getrow('select mfa_required from customers where id = %s', (customer_id,))
    if qry['success']:
        if qry['data']['mfa_required']:
            logger.debug('disabling mfa')
            qry = db_do('update customers set mfa_required = false where id = %s', (customer_id,))
            return qry['success']
        else:
            logger.debug('enabling mfa')
            qry = db_do('update customers set mfa_required = true where id = %s', (customer_id,))
            return qry['success']
    else:
        logger.error('query failed')
        return False

def saveuser(formdata):
    result = {'success': False, 'errors': []}

    email = formdata['email']
    nickname = formdata['nickname']
    # check email and nick are unique
    if 'user_id' in formdata:
        logger.debug('editing user - checking for duplicates')
        sql = 'select email, nickname from users where id != %s and (email = %s or nickname = %s)'
        params = (formdata['user_id'], email, nickname)
    else:
        logger.debug('checking for duplicate email or nickname')
        sql = 'select email, nickname from users where email = %s or nickname = %s'
        params = (email, nickname)

    qry = db_getdict(sql, params)
    duplicates = qry['data']

    if duplicates:
        logger.debug('duplicates found, generating flashes')
        for row in duplicates:
            logger.debug(repr(row))
            for value in row.values():
                logger.debug(value)
                if value == email:
                    result['errors'].append('A user with email ' + email + ' is already registered')
                    logger.debug('aborting user registration, email already registered')

                if value == nickname:
                    result['errors'].append('A user with nickname ' + nickname + ' is already registered')
                    logger.debug('aborting user registration, nickname already registered')

        return result
    else:
        logger.debug('email and nickname unique, continuing')

    # handle boolean values
    keys = ['admin', 'disabled']
    values = []
    for key in keys:
        if key in formdata and formdata[key]:
            # if granting admin or disabling user, no license check needed
            if key == 'disabled' and 'user_id' in formdata:
                logger.debug('Disabling an existing user, checking they are not the last admin user')
                qry = db_getcol('select id from users where customer_id = %s and admin is true and disabled is false',
                                   (session['customer_id'],))
                if qry['success']:
                    if len(qry['data']) == 1 and int(qry['data'][0]) == int(formdata['user_id']):
                        logger.info('Refusing to disable the last remaining admin user')
                        values.append(False)
                        result['errors'].append('Cannot disable the last remaining admin user')
                    else:
                        logger.debug('enabled admin count: ' + str(len(qry['data'])))
                        logger.debug('edited user: ' + str(formdata['user_id']) + ' , last admin: ' + str(qry['data'][0]))

                        values.append(True)
                else:
                    logger.error('Query failed')
                    # if there's an error, don't change the admin flag
                    keys.remove('disabled')
                    result['errors'].append('Error editing the user, please report this')
            else:
                values.append(True)

        else:
            if key == 'disabled' and 'user_id' in formdata:
                logger.debug('enabling user, checking licenses')
                if 'user_id' in formdata:
                    check = has_free_license(user_id = formdata['user_id'])
                else:
                    check = has_free_license()
                # please don't remove this. it enables us to continue supporting this project
                # editing or removing the lines below will put you in breach of your license
                if check['success']:
                    if check['has_free_license']:
                        values.append(False)
                    else:
                        result['errors'].append('License limit reached. You can disable users to free licenses or contact support to buy more')
                        values.append(True)
                else:
                    logger.error('failed to check licenses')
                    result['errors'] += check['errors']
                    values.append(True)

            elif 'user_id' in formdata:
                # if the admin box is unchecked
                logger.debug('removing admin rights from existing user, checking if this is the last admin')
                qry = db_getcol('select id from users where customer_id = %s and admin is true and disabled is false',
                                       (session['customer_id'],))
                if qry['success']:
                    if len(qry['data']) == 1 and int(qry['data'][0]) == int(formdata['user_id']):
                        logger.info('Refusing to remove admin rights from last remaining admin user')
                        values.append(True)
                        result['errors'].append('Cannot remove admin rights from the last remaining admin user')
                    else:
                        values.append(False)
                else:
                    logger.error('Query failed')
                    # if there's an error, don't change the admin flag
                    keys.remove('admin')
            else:
                logger.debug('creating a non-admin user')
                values.append(False)

    for key, value in formdata.items():
        if key not in ['submit', 'csrf_token', 'user_id', 'admin', 'disabled'] and value:
            keys.append(key)
            values.append(value.strip())

    if 'user_id' in formdata:
        logger.debug('updating user info')
        #TODO would be nice to check if email is being updated, and send a confirmation to the new address
        updatesql = get_pg_update_sql('users', keys, 'where id = %s')
        values.append(formdata['user_id'])
        #logger.debug(updatesql)
        #logger.debug(repr(values))
        qry = db_do(updatesql, tuple(values))
        if qry['success']:
            logger.debug('user updated')
            if 'disabled' in formdata and formdata['disabled']:
                qry = db_getrow('select certfp, oldcertfp from users where id = %s', (formdata['user_id'],))
                if qry['success']:
                    cert_revoked = False
                    if qry['data']['certfp']:
                        status = revoke_cert(email)
                        if status['success']:
                            cert_revoked = True
                        else:
                            result['errors'].append('Failed to revoke certificate on disabling user', 'error')
                    if qry['data']['oldcertfp']:
                        status = revoke_renewed(email)
                        if status['success']:
                            cert_revoked = True
                        else:
                            result['errors'].append('Failed to revoke old certificate on disabling user', 'error')

                    if not result['errors']:
                        if cert_revoked:
                            flash('User disabled and client certificate revoked', 'info')
                        else:
                            flash('User updated', 'info')

            elif not result['errors']:
                flash('User updated', 'info')
        else:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to update user')
            result['errors'].append('Failed to update user, application error')

        return result
    else:
        logger.debug('creating new user with email ' + email + ' and nickname ' + nickname)

        customer_id = session['customer_id']
        keys.append('customer_id')
        values.append(customer_id)

        sql = get_pg_insert_sql('users', keys, returning='id')
        qry = db_do(sql, tuple(values))
        if qry['success']:
            user_id = qry['data']
            logger.debug('user added with id ' + str(user_id))
            reset_pass(formdata['email'])
            create_dummy('pentest', user_id=user_id)
            result['success'] = True
            flash('User created', 'info')
            return result
        else:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to add user')
            result['errors'].append('Failed to add user, application error')
            return result

def has_free_license(user_id=None):
    # please don't remove this. it enables us to continue supporting this project
    # editing or removing the lines below would be in breach of your license
    logger.debug('checking licenses')
    result = {'errors': [], 'success': True, 'has_free_license': True}

    sql = 'select licenses from customers where id = %s\
           union all\
           select count(id) as num_users from users where customer_id = %s and disabled is false'
    prm = [ session['customer_id'] ] * 2

    # if check is triggered by an edit to existing user, exclude that user from license count
    if user_id:
        sql += ' and id != %s'
        prm.append(user_id)

    qry = db_getcol(sql, tuple(prm))
    if qry['success']:
        if qry['data']:
            #logger.debug(repr(qry['data']))
            licenses, active_users = qry['data']
            if int(active_users) >= int(licenses):
                result['has_free_license'] = False
                logger.info('license limit reached')
        else:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'Empty result set in licenses query')
            result['errors'].append('Error retrieving user and license information')
    else:
        logger.error('query failed')
        result['errors'].append('System error')

    if result['errors']:
        result['success'] = False
        result['has_free_license'] = False

    return result

def check_env():
    '''Used as a CLI command to run instance checks - network connectivity, DNS, email, python updates'''
    targets = ['deb.debian.org', 'pypi.org', 'updates.haxhq.com']

    if email_enabled:
        app = Flask(__name__)
        app.config.from_object('def_settings')
        smtp_server = app.config['SMTP_SERVER']
        smtp_port = app.config['SMTP_PORT']
        targets.append(smtp_server)

    resolver = dns.resolver.Resolver()
    if not resolver._nameservers:
        print('No DNS resolvers detected, is the host networking fully set up?')

    resolved = set()
    for host in targets:
        #msg = 'Resolving ' + host
        address = resolve(host)
        for ipv in address:
            if address[ipv]:
                #msg += ', ' + ipv + ': ' + address[ipv]
                #print(host + ' resolved to ' + repr(address[ipv]))
                resolved.add(host)

        #print(msg)

    if len(resolved) == len(targets):
        print('DNS checks successful')
    elif resolved:
        for host in targets:
            if host not in resolved:
                print('Failed to resolve ' + host)

        print('Some DNS queries failed, this may or may not be an issue with host/network configuration')
        print('Configured DNS resolvers: ' + ', '.join(resolver._nameservers))
    else:
        print('DNS resolution failed. OS and/or python updates will likely fail and email sending may not be available')
        print('Configured DNS resolvers: ' + ', '.join(resolver._nameservers))

    if resolved:
        accessible = set()
        for host in resolved:
            if host == smtp_server:
                status = send_email('info@haxhq.com', 'Email test', 'Testing email server settings')
                if status['success']:
                    accessible.add(host)
                else:
                    print('Failed to send test email through ' + smtp_server)

                continue

            url = 'https://' + host + ':5885' if host == 'updates.haxhq.com' else 'https://' + host
            try:
                r = requests.get(url, timeout=2)
                accessible.add(host)
            except:
                pass

        resolved.remove(host)

        if len(accessible) == len(resolved):
            print('Connectivity checks successful')
        elif accessible:
            for host in resolved:
                if host == smtp_server:
                    continue

                url = 'https://' + host + ':5885' if host == 'updates.haxhq.com' else 'https://' + host
                if host not in accessible:
                    print('Failed to connect to: ' + url)

            print('Some HTTPS requests failed, this may be down to temporary issues with remote hosts')
        else:
            print('No HTTPS connectivity detected. OS and/or python updates will likely fail.')

    print('All checks completed')

def get_os_updates():
    '''Check if any packages are upgradable and return a list. Does not need root'''
    result = {'success': False, 'error': None, 'data': []}

    output_bytes = None
    try:
        output_bytes = subprocess.check_output(['/usr/bin/aptitude', '-ys', 'upgrade'])
    except Exception as e:
        result['error'] = 'Aptitude error while checking system updates'
        logger.error(result['error'])
        logger.error(repr(e))
        return result

    if output_bytes:
        output = output_bytes.decode('UTF-8').strip()
        m = re.search('The following packages will be upgraded:[\r\n\s]+(.+)$', output, re.MULTILINE)
        if m:
            result['data'] = m[1].strip().split(' ')
            logger.debug('OS updates pending: ' + repr(result['data']))
            result['success'] = True
        else:
            m = re.search('No packages will be installed, upgraded, or removed.', output, re.MULTILINE)
            if m:
                logger.debug('No OS updates available')
                result['success'] = True

        if not m:
            result['error'] = 'Unexpected aptitude output'
            logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])

    return result

def get_xhq_updates():
    '''Check for HaxHQ updates'''
    result = {'success': False, 'error': None, 'data': []}

    app = Flask(__name__)
    app.config.from_object('def_settings')
    git_user = app.config['GIT_USER']
    git_pass = app.config['GIT_PASS']

    try:
        fetchout = subprocess.check_output(['/usr/bin/git', 'fetch', '-q', 'https://' + git_user + ':' + git_pass + '@updates.haxhq.com:5885/haxhq', 'master'])
    except Exception as e:
        result['error'] = 'Git error while fetching remote status'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        logging.error(repr(e))
        return result

    logger.debug('fetched ok')
    logger.debug(fetchout.decode('UTF-8'))

    try:
        # fetching updates against ..origin/master fails, seems like a bug in git
        commitdata = subprocess.check_output(['/usr/bin/git', 'log', '--pretty=reference', '..FETCH_HEAD'])
    except Exception as e:
        result['error'] = 'Git error while checking commits'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        logging.error(repr(e))
        return result

    logger.debug('git log ok')
    logger.debug(commitdata.decode('UTF-8'))

    commits = []
    for c in commitdata.decode('UTF-8').strip().split('\n'):
        if c:
            m = re.match('^[a-z0-9]{7}\s\((.+)\)$', c)
            if m:
                text = m[1]
                logger.debug(text)
                m = re.match('^(.+),\s([0-9-]{10})$', text)
                if m:
                    msg = m[1]
                    date = m[2]
                    commits.append(date + ': ' + msg)
                else:
                    logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to extract date and message from ' + text)
            else:
                logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to extract text from commit ' + c)
        else:
            logger.warn('ignoring empty line in commit data')

    #logger.debug(repr(commits))

    result['data'] = commits
    result['success'] = True
    return result

def get_pip_updates():
    '''Check for available python package updates and return a list'''
    #TODO all update data should be cached in db to avoid redundant checks
    result = {'success': False, 'error': None, 'data': []}
    try:
        output_bytes = subprocess.check_output(['pip', 'list', '--outdated', '--format', 'json', '--cache-dir', '../../'])
    except Exception as e:
        logger.error(repr(e))
        result['error'] = 'Failed to retrieve a list of outdated packages with pip'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    outdated_list = json.loads(output_bytes.decode('UTF-8'))
    result['data'] = { x.pop('name'): x for x in outdated_list }

    result['success'] = True
    return result

def get_updates(x=None):
    '''Used to flag availability of all types of updates. Returns a list of available update types e.g.
       ['OS packages', 'Python packages', 'HaxHQ']'''
    result = {}

    if x == 'HaxHQ':
        return get_xhq_updates()
    elif x == 'OS':
        return get_os_updates()
    elif x == 'Python':
        return get_pip_updates()
    else: # probably unnecessary?
        x = get_xhq_updates()
        if x['success'] and x['data']:
            logger.debug(str(len(x['data'])) + ' commits to pull')
            result['HaxHQ'] = x['data']
        elif x['error']:
            result['HaxHQ'] = x

        x = get_os_updates()
        if x['success'] and x['data']:
            logger.debug(str(len(x['data'])) + ' os packages upgradable')
            result['OS packages'] = x['data']
        elif x['error']:
            result['OS packages'] = x

        x = get_pip_updates()
        if x['success'] and x['data']:
            logger.debug(str(len(x['data'])) + ' Python packages upgradable')
            result['Python packages'] = x['data']
        elif x['error']:
            result['Python packages'] = x

        return result

def update_hahxq():
    result = {'success': False, 'error': None}
    app = Flask(__name__)
    app.config.from_object('def_settings')
    git_user = app.config['GIT_USER']
    git_pass = app.config['GIT_PASS']

    logger.debug('/usr/bin/git pull https://' + git_user + ':' + git_pass + '@updates.haxhq.com:5885/haxhq master')
    try:
        gitpull = ['/usr/bin/git', 'pull', '-q', 'https://' + git_user + ':' + git_pass + '@updates.haxhq.com:5885/haxhq', 'master']
        _exit = subprocess.run(gitpull)
    except Exception as e:
        result['error'] = 'Git error while pulling updates'
        logging.error(repr(e))
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    # check for queued database schema updates
    sqlpath = 'update.sql'
    logpath = 'update.log'
    _sql = ''
    _log = ''
    if os.path.isfile(sqlpath) and os.stat(sqlpath).st_size > 0:
        logger.debug('schema updates queued')
        #TODO need checks here that files are readable/writeable
        with open(sqlpath, 'r') as f:
            _sql = f.read()

        if os.path.isfile(logpath) and os.stat(logpath).st_size > 0:
            logger.debug('previously executed updates seen')
            with open(logpath, 'r') as f:
                _log = f.read()

        if _sql != _log:
            logger.info('new update to db schema queued, executing')
            qry = db_do(_sql)
            if qry['success']:
                logger.info('schema update done')
                with open(logpath, 'w') as f:
                    f.write(_sql)
                    logger.debug('log file updated')
            else:
                #TODO: error messages could get clobbered, convert to a list
                result['error'] = 'schema update failed'
                logger.error('schema update failed: {}'.format(qry['error']))
        else:
            logger.debug('ignoring schema update identical to a previously executed one')
    else:
        logger.debug('no schema updates queued')

    if _exit.returncode == 0:
        logger.debug('Successfully pulled updates, getting gunicorn pid')
        pid = None
        try:
            b = subprocess.check_output(['/usr/bin/ps', '-C', 'gunicorn', 'fch', '-o', 'pid'])
            pid = b.decode('UTF-8').split('\n')[0].strip()
        except Exception as e:
            logger.error('Error applying updates: ' + repr(e))
            result['error'] = 'Error applying updates'
            logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])

        if pid:
            logger.debug('Gunicorn PID is ' + pid)
            _exit = subprocess.run(['/usr/bin/kill', '-HUP', pid])
            if _exit.returncode == 0:
                result['success'] = True
                logger.info('Updates applied successfuly')
            else:
                logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to restart gunicorn after pulling updates')
                result['error'] = 'Failed to reload application after applying updates'
    else:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to retrieve updates with git pull')
        result['errors'] = 'Error applying updates, please contact support'

    return result

def update_python():
    '''Install Python environment package updates'''
    result = {'success': False, 'error': None}
    logger.debug('pip list -o |/usr/bin/cut -f1 -d" " |/usr/bin/tr " " "\\n" |/usr/bin/awk "{if(NR>=3)print}" |/usr/bin/cut -d" " -f1 |/usr/bin/xargs -n1 pip install -U')
    try:
        _exit = os.system('pip list -o |/usr/bin/cut -f1 -d" " |/usr/bin/tr " " "\\n" |/usr/bin/awk "{if(NR>=3)print}" |/usr/bin/cut -d" " -f1 |/usr/bin/xargs -n1 pip install -U')
    except Exception as e:
        logger.error(repr(e))
        result['error'] = 'Failed to install pip updates'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    if _exit == 0:
        result['success'] = True

    return result

def collect_logs():
    '''Extract and return warn and error logs from today's log'''
    result = {'success': False, 'error': None, 'data': []}
    filename = '../logs/haxhq.log'

    if os.path.isfile(filename):
        try:
            f = open(filename, "r")
        except FileNotFoundError as e:
            result['error'] = f"The file '{filename}' was not found: {e}"
            logger.warn(result['error'])
            return result
        except PermissionError as e:
            result['error'] = f"You do not have permission to read the file '{filename}': {e}"
            logger.warn(result['error'])
            return result
        except Exception as e:
            result['error'] = f"An unexpected error occurred while reading '{filename}': {e}"
            logger.warn(result['error'])
            return result
    else:
        result['error'] = f"The file '{filename}' does not exist."
        logger.warn(result['error'])
        return result

    last_app_reload = None
    stacktrace = None
    for i, line in enumerate(f):
        if line.startswith('Traceback (most recent call last):'):
            logger.debug(str(i) + ' traceback start')
            stacktrace = [line]
            continue
        elif stacktrace and (re.match('^  |^(?!\[20|20).*', line)):
            logger.debug(str(i) + ' traceback line')
            stacktrace.append(line)
            continue
        elif stacktrace:
            logger.debug(str(i) + ' traceback finished')
            result['data'] += stacktrace
            stacktrace = None

        if re.search('ERROR|WARNING', line):
            logger.debug(str(i) + ' error line')
            if line.endswith('was sent SIGTERM!\n'):
                m = re.match('^\[\d+\-\d{2}\-\d{2}\s([\d:]{8}).*', line)
                if m:
                    time = m[1]
                    if last_app_reload == time:
                        continue
                    else:
                        last_app_reload = time
                        result['data'].append(str(i) + ' # ' + 'app restarted')
                else:
                    logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to extract date from error log')
                    logger.error('===' + line)
                    break
            else:
                result['data'].append(str(i) + ' # ' + line)

    logger.debug('Log search found ' + str(len(result['data']))  + ' lines')
    result['success'] = True
    return result

def issue_cert(email, password):
    '''Issue a client certificate using a local, self-signed CA'''
    result = {'success': False, 'error': None, 'data': []}
    logger.debug('issuing certificate for ' + email)

    app = Flask(__name__)
    app.config.from_object('def_settings')
    cakey = app.config['CA_KEY']
    cadir = app.config['CADIR']

    easyrsa = cadir + '/easyrsa3/easyrsa'
    if not os.path.isfile(easyrsa):
        result['error'] = 'Not found: ' + easyrsa
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    easyrsacmd = easyrsa + ' --vars='+ cadir +'/easyrsa3/vars --pki='+ cadir +'/pki'
    p = pexpect.spawn(easyrsacmd + ' --subject-alt-name=email:' + email + ' gen-req ' + email)
    if logger.level == 10:
        p.logfile = sys.stdout.buffer

    #output = p.read()
    output = ''
    i = p.expect(['Enter PEM pass phrase:', "Type the word 'yes' to continue, or any other input to abort.", pexpect.EOF])
    if i == 1:
        p.sendline('yes')
        logger.debug('confirmed certificate overwrite')
        p.expect('Enter PEM pass phrase:')
    elif i == 2:
        result['error'] = 'Failed to issue certificate: unexpected output'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        logger.error(output)
        return result

    p.sendline(password)
    logger.debug('passed pem pass')
    i = p.expect(['Verifying - Enter PEM pass phrase:', pexpect.EOF])
    if i == 1:
        result['error'] = 'Failed to issue certificate: unexpected output'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        logger.error(output)
        return result

    p.sendline(password)
    logger.debug('repeated pem pass')
    i = p.expect(['.*Common Name \(eg: your user, host, or server name\).*', pexpect.EOF])
    if i == 1:
        result['error'] = 'Failed to issue certificate: unexpected output'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        logger.error(output)
        return result

    p.sendline(email)
    logger.debug('passed email')
    p.expect('.*Private-Key and Public-Certificate-Request files created..*')

    logger.debug('key and csr created')
    p.kill(0)

    certreq = cadir + '/pki/reqs/' + email + '.req'
    if os.path.isfile(certreq):
        logger.debug('csr file exists')
    else:
        result['error'] = 'Failed to create certificate request'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    keypath = cadir + '/pki/private/' + email + '.key'
    if os.path.isfile(keypath):
        logger.debug('private key file exists')
    else:
        result['error'] = 'Failed to create certificate private key'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    p = pexpect.spawn(easyrsacmd + ' --subject-alt-name=email:' + email + ' sign-req client ' + email)
    if logger.level == 10:
        p.logfile = sys.stdout.buffer
    p.expect('.*Confirm request details: .*')
    p.sendline('yes')
    p.expect('.*Enter pass phrase for ' + cadir + '/pki/private/ca.key:')
    p.sendline(cakey)
    p.expect('.*Certificate created.*')
    p.kill(0)

    certpath = cadir + '/pki/issued/' + email + '.crt'
    if os.path.isfile(certpath):
        logger.debug('certificate created')
        store_client_cert_fp(email, 'cert', certpath)
    else:
        result['error'] = 'Failed to create certificate'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    return export_p12(email, password, cadir=cadir, cakey=cakey, easyrsacmd=easyrsacmd)

def store_client_cert_fp(email, certtype, certpath):
    '''Store issued client certificate fingerprint as the users current (or old) certificate.
       Enables staged revokation of old certificates after renewal. This in turn allows the new certificate to be
       downloaded over https as the old certificate remains valid until the first login with the new certificate.'''
    result = {'success': False, 'error': None, 'data': []}
    logger.debug('Storing '+ certtype +' fingerprint for ' + email)

    certfp = None
    certexp = None
    fpout = subprocess.check_output(['/usr/bin/openssl', 'x509', '-fingerprint', '-noout', '-in', certpath])
    if fpout:
        fpstr = fpout.decode('UTF-8')
        certfp = fpstr.split('=')[1].strip().replace(':', '').lower()
        if not (certfp and len(certfp) == 40):
            result['error'] = 'Failed to extract certificate fingerprint'
            logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
            logger.error(fpstr)
            logger.error(fp)
    else:
        result['error'] = 'OpenSSL command failed to retrieve fingerprint information'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        certfp = None

    if certtype == 'cert':
        dateout = subprocess.check_output(['/usr/bin/openssl', 'x509', '-enddate', '-noout', '-in', certpath])
        if dateout:
            datestr = dateout.decode('UTF-8')
            certexp = datestr.split('=')[1].strip()
            if not certexp:
                result['error'] = 'Failed to extract certificate expiry date'
                logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
                logger.error(datestr)
                logger.error(certexp)
                return result

        qry = db_do("update users set certfp = %s, certexp = %s where email = %s", (certfp, certexp, email))
    elif certtype == 'oldcert':
        qry = db_do("update users set oldcertfp = %s where email = %s", (certfp, email))
    else:
        logger.error('Unrecognised cert type')
        result['error'] = 'Bad certtype parameter, aborting'
        return result

    if qry['success']:
        logger.debug('Database updated')
        result['success'] = True
    else:
        result['error'] = 'Failed to update user entry in db after issuing client cert'
        logger.error(result['error'])

    return result

def export_p12(email, password, cadir=None, cakey=None, easyrsacmd=None):
    '''Create a pkcs12 certificate from existing crt and key'''
    result = {'success': False, 'error': None, 'data': []}
    logger.info('Exporting pkcs12 certificate for ' + email)

    if not (cadir and cakey and easyrsacmd):
        app = Flask(__name__)
        app.config.from_object('def_settings')
        cakey = app.config['CA_KEY']
        cadir = app.config['CADIR']

        easyrsa = cadir + '/easyrsa3/easyrsa'
        if not os.path.isfile(easyrsa):
            result['error'] = 'Not found: ' + easyrsa
            logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
            return result

        easyrsacmd = easyrsa + ' --vars='+ cadir +'/easyrsa3/vars --pki='+ cadir +'/pki'

    p12path = cadir + '/pki/private/' + email + '.p12'
    p = pexpect.spawn(easyrsacmd + ' export-p12 ' + email + ' legacy')
    if logger.level == 10:
        p.logfile = sys.stdout.buffer
    p.expect('.*Enter pass phrase for.*')
    p.sendline(password)
    p.expect('Enter Export Password:')
    p.sendline(password)
    p.expect('Verifying - Enter Export Password:')
    p.sendline(password)
    p.expect('Successful export of p12 file.*')
    p.kill(0)

    if os.path.isfile(p12path):
        logger.debug('p12 certificate exported')
        result['success'] = True
        result['data'] = [p12path]
        logger.debug(repr(result))
        return result
    else:
        result['error'] = 'Failed to export .p12 certificate'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

def init_ca():
    '''Initialise a local CA'''
    result = {'success': False, 'error': None, 'data': []}
    logger.debug('Creating a root signing CA')

    app = Flask(__name__)
    app.config.from_object('def_settings')
    cakey = app.config['CA_KEY']
    cadir = app.config['CADIR']
    orgname = app.config['ORG_NAME']
    domain = app.config['SENDER_DOMAIN']

    easyrsa = cadir + '/easyrsa3/easyrsa'
    if not os.path.isfile(easyrsa):
        result['error'] = 'Not found: ' + easyrsa
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    easyrsacmd = easyrsa + ' --vars='+ cadir +'/easyrsa3/vars --pki='+ cadir +'/pki'

    p = pexpect.spawn(easyrsacmd + ' init-pki')
    if logger.level == 10:
        p.logfile = sys.stdout.buffer
    i = p.expect(["'init-pki' complete;.*", '  Confirm removal:'])
    if i == 1:
        p.sendline('yes')
        p.expect("'init-pki' complete;.*")

    p.kill(0)
    if not os.path.isdir(cadir + '/pki'):
        result['error'] = 'Failed to initialise pki'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    p = pexpect.spawn(easyrsacmd + ' build-ca')
    if logger.level == 10:
        p.logfile = sys.stdout.buffer
    p.expect('Enter New CA Key Passphrase:')
    p.sendline(cakey)
    p.expect('Confirm New CA Key Passphrase:')
    p.sendline(cakey)
    p.expect('Common Name \(eg: your user, host, or server name\).*')
    p.sendline(orgname + ' ECC Root CA')
    p.expect('CA creation complete.*')
    p.kill(0)

    if not os.path.isfile(cadir + '/pki/ca.crt'):
        result['error'] = 'Failed to create CA'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    _exit = os.system('/usr/bin/cp '+ cadir +'/pki/ca.crt static/ca.crt')
    if _exit != 0:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'Failed to copy ca.crt to static/')

    # remove now obsolete cert info from users table
    qry = db_do('update users set certfp = null, oldcertfp = null, certexp = null')
    if not qry['success']:
        logger.error('Failed to clear certificate information from database')
        if session:
            flash('Failed to clear certificate information from database')

    with open(cadir + '/pki/crlnumber', 'w') as f:
        f.write('00000000')

    status = app_cert_issue()
    if status['success']:
        logger.debug('issued a fresh server certificate after re-initialising the CA')
    else:
        logger.error('Failed to issue a fresh server certificate after re-initialising the CA')

    return generate_crl()

def revoke_cert(email):
    '''Revoke a user's client certificate by email and issue an updated crl'''
    result = {'success': False, 'error': None, 'data': []}
    logger.debug('Revoking client cert for user ' + email)

    app = Flask(__name__)
    app.config.from_object('def_settings')
    cakey = app.config['CA_KEY']
    cadir = app.config['CADIR']

    easyrsa = cadir + '/easyrsa3/easyrsa'
    if not os.path.isfile(easyrsa):
        result['error'] = 'Not found: ' + easyrsa
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    easyrsacmd = easyrsa + ' --vars='+ cadir +'/easyrsa3/vars --pki='+ cadir +'/pki'

    try:
        p = pexpect.spawn(easyrsacmd + ' revoke ' + email)
        if logger.level == 10:
            p.logfile = sys.stdout.buffer
        i = p.expect(['.*Continue with revocation:', 'Unable to revoke as no certificate was found.'])
        if i == 1:
            result['error'] = 'Unable to revoke as no certificate was found'
            logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
            return result

        p.sendline('yes')
        p.expect('Enter pass phrase for.*')
        p.sendline(cakey)
        i = p.expect(['Revocation was successful.*', 'Could not read CA private key.*'])
        if i == 1:
            result['error'] = 'Could not read CA private key'
            logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
            return result
        else:
            p.kill(0)
    except Exception as e:
        result['error'] = 'Failed to revoke certificate'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        logger.error(e)
        return result

    logger.debug('certificate revoked, updating database')
    qry = db_do('update users set certfp = null, certexp = null where email = %s', (email,))
    if not qry['success']:
        logger.error('query failed')

    return generate_crl()

def generate_crl(reload=True):
    '''Generate a fresh CRL and reload Nginx to apply it if flag is set'''
    result = {'success': False, 'error': None, 'data': []}
    logger.debug('Generating a new CRL')

    app = Flask(__name__)
    app.config.from_object('def_settings')
    cakey = app.config['CA_KEY']
    cadir = app.config['CADIR']

    easyrsa = cadir + '/easyrsa3/easyrsa'
    if not os.path.isfile(easyrsa):
        result['error'] = 'Not found: ' + easyrsa
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    easyrsacmd = easyrsa + ' --vars='+ cadir +'/easyrsa3/vars --pki='+ cadir +'/pki'
    try:
        p = pexpect.spawn(easyrsacmd + ' gen-crl', timeout=600)
        if logger.level == 10:
            p.logfile = sys.stdout.buffer
        p.expect('Enter pass phrase for.*')
        p.sendline(cakey)
        p.expect('An updated CRL has been created:')
        p.kill(0)
    except Exception as e:
        result['error'] = 'Failed to create updated CRL'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        logger.error(e)
        return result

    if reload:
        status = reload_nginx()
        if status['success']:
            result['success'] = True
        else:
            result['error'] = status['error'] + '  Certificate was revoked but will be accepted until nginx is reloaded!'
    else:
        result['success'] = True

    return result

def reload_nginx():
    '''Reload nginx config'''
    result = {'success': False, 'error': None, 'data': []}
    logger.info('Reloading nginx')

    try:
        _exit = subprocess.run(['/usr/bin/sudo', '/usr/sbin/nginx', '-s', 'reload'])
    except Exception as e:
        logger.error(repr(e))
        result['error'] = 'Failed to reload nginx.'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    if _exit.returncode == 0:
        result['success'] = True
        time.sleep(1)
    else:
        # permission errors don't seem to trigger an exception above
        result['error'] = 'Failed to reload nginx.'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])

    return result

def renew_cert(email, password):
    '''Renew the certificate for the user'''
    result = {'success': False, 'error': None, 'data': []}
    logger.debug('Renewing client cert for user ' + email)

    app = Flask(__name__)
    app.config.from_object('def_settings')
    cakey = app.config['CA_KEY']
    cadir = app.config['CADIR']

    easyrsa = cadir + '/easyrsa3/easyrsa'
    if not os.path.isfile(easyrsa):
        result['error'] = 'File not found: local CA directory might be wrong'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        logger.error('Not found: ' + easyrsa)
        return result

    easyrsacmd = easyrsa + ' --vars='+ cadir +'/easyrsa3/vars --pki='+ cadir +'/pki'

    if os.path.isfile(cadir + '/pki/renewed/issued/' + email + '.crt'):
        logger.error('Certificate already renewed, returning the last issued one')
        if os.path.isfile(cadir + '/pki/issued/' + email + '.crt'):
            return export_p12(email, password, cadir=cadir, cakey=cakey, easyrsacmd=easyrsacmd)

    try:
        p = pexpect.spawn(easyrsacmd + ' renew ' + email)
        if logger.level == 10:
            p.logfile = sys.stdout.buffer
    except Exception as e:
        result['error'] = 'Failed to renew certificate'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        logger.error(e)
        return result

    i = p.expect(['.*Continue with renewal:', 'Missing certificate file:', 'Cannot renew this certificate, a conflicting file exists:'])
    if i == 1:
        result['error'] = 'Unable to renew as the certificate was not found'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result
    elif i == 2:
        result['error'] = 'Certificate already renewed and old certificate not yet revoked'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    p.sendline('yes')
    p.expect('Enter pass phrase for.*')
    p.sendline(cakey)
    i = p.expect(['Renew was successful.', 'Could not read CA private key.*'])
    if i == 1:
        result['error'] = 'Could not read CA private key'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result
    else:
        p.kill(0)
        logger.info('Renewed certificate for ' + email)


    certpath = cadir + '/pki/issued/' + email + '.crt'
    if os.path.isfile(certpath):
        if (time.time() - os.stat(certpath).st_mtime) > 30:
            result['error'] = 'Certificate file is older than expected, renewal error'
            logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
            return result
        else:
            logger.debug('.crt file created, updating database')
            store_client_cert_fp(email, 'cert', certpath)
            store_client_cert_fp(email, 'oldcert', cadir + '/pki/renewed/issued/' + email + '.crt')
    else:
        result['error'] = 'Not found: ' + certpath
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    return export_p12(email, password, cadir=cadir, cakey=cakey, easyrsacmd=easyrsacmd)

def enable_cert_auth():
    '''Update nginx config to require and verify client certificates and reload it'''
    result = {'success': False, 'error': None, 'data': []}
    app = Flask(__name__)
    app.config.from_object('def_settings')
    if 'CERT_AUTH_ENABLED' in app.config and not app.config['CERT_AUTH_ENABLED']:
        result['error'] = 'Certificate authentication cannot be enabled. Please set CERT_AUTH_ENABLED=True first.'
        return result

    logger.warn('Enabling client certificate authentication')

    try:
        _exit = os.system("/usr/bin/sudo /usr/bin/ln -s -f /etc/nginx/sites-available/haxhq-certauth /etc/nginx/sites-enabled/haxhq")
    except Exception as e:
        logger.error(repr(e))
        result['error'] = 'Failed to enable client certificate authentication'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    if _exit == 0:
        return reload_nginx()
    else:
        # permission errors don't seem to trigger an exception above
        result['error'] = 'Failed to enable client certificate authentication'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

def disable_cert_auth():
    '''Update nginx config to stop requiring client certificates and reload it'''
    result = {'success': False, 'error': None, 'data': []}
    logger.warn('Disabling client certificate authentication')

    try:
        _exit = os.system('/usr/bin/sudo /usr/bin/ln -s -f /etc/nginx/sites-available/haxhq /etc/nginx/sites-enabled/haxhq')
    except Exception as e:
        logger.error(repr(e))
        result['error'] = 'Failed to disable client certificate authentication'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    if _exit == 0:
        if session and 'cert_remaining' in session:
           del session['cert_remaining']
        return reload_nginx()
    else:
        # permission errors don't seem to trigger an exception above
        result['error'] = 'Failed to disable client certificate authentication'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

def get_client_cert(email, password):
    '''Return the path to a valid .p12 file for the current user.
    If the current user doesn't have a certificate, generate one. If the user has a certificate, renew it.
    If the user has renewed before but not yet used the new certificate, generate the p12 from the current user's client certificate.'''
    result = {'success': False, 'error': None, 'data': []}
    logger.info('Retrieving client certificate for ' + email)

    qry = db_getrow('select id, certfp, oldcertfp from users where email = %s', (email,))

    if not qry['success']:
        result['error'] = 'Query failed'
        return result

    # this can be used from the cli, ensure email is correct
    if not qry['data']:
        result['error'] = 'No registered user with email ' + email
        return result

    if not qry['data']['certfp']:
        return issue_cert(email, password)
    elif not qry['data']['oldcertfp']:
        return renew_cert(email, password)
    else:
        return export_p12(email, password)

def revoke_renewed(email, reload=True):
    '''Revoke the user's old certificate after a new one was issued using renew_cert'''
    result = {'success': False, 'error': None, 'data': []}
    logger.info('Revoking old client cert for user ' + email)

    app = Flask(__name__)
    app.config.from_object('def_settings')
    cakey = app.config['CA_KEY']
    cadir = app.config['CADIR']

    easyrsa = cadir + '/easyrsa3/easyrsa'
    if not os.path.isfile(easyrsa):
        result['error'] = 'Not found: ' + easyrsa
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    easyrsacmd = easyrsa + ' --vars='+ cadir +'/easyrsa3/vars --pki='+ cadir +'/pki'

    try:
        p = pexpect.spawn(easyrsacmd + ' revoke-renewed ' + email)
        if logger.level == 10:
            p.logfile = sys.stdout.buffer
        i = p.expect(['.*Continue with revocation:', 'Missing certificate file:'])
        if i == 1:
            result['error'] = 'Unable to revoke as no certificate was found'
            logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
            return result

        p.sendline('yes')
        p.expect('Enter pass phrase for.*')
        p.sendline(cakey)
        i = p.expect(['Revocation was successful.', 'Could not read CA private key.*'])
        if i == 1:
            resut['error'] = 'Could not read CA private key'
            logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
            return result
        else:
            p.kill(0)
    except Exception as e:
        result['error'] = 'Failed to revoke old certificate after issuing a renewed one'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        logger.error(e)
        return result

    qry = db_do('update users set oldcertfp = null where email = %s', (email,))
    if not qry['success']:
        logger.error('Query failed')

    status = generate_crl(reload=reload)
    if status['success']:
        result['success'] = True
    else:
        logger.error('pkcs12 export successful but CRL update failed. Old certificate is revoked but can still be used.')
        result['error'] = status['error']

    return result

def app_cert_issue():
    '''Issue a server certificate for the local HaxHQ instance. CN is haxhq.SENDER_DOMAIN'''
    result = {'success': False, 'error': None, 'data': []}
    logger.debug('issuing a server certificate for the local HaxHQ instance')

    app = Flask(__name__)
    app.config.from_object('def_settings')
    cakey = app.config['CA_KEY']
    cadir = app.config['CADIR']
    cn = 'haxhq.'+ app.config['SENDER_DOMAIN']

    ip = None
    ip6 = None
    ipout = subprocess.check_output(['/usr/bin/ip', 'addr', 'show', 'scope', 'global'])
    ipout_list = ipout.decode('utf8').split('\n')
    for line in ipout_list:
        line = line.strip()
        if line.startswith('inet6'):
            ip6 = line.split(' ')[1][:-3]
        elif line.startswith('inet'):
            ip = line.split(' ')[1][:-3]

    easyrsa = cadir + '/easyrsa3/easyrsa'
    if not os.path.isfile(easyrsa):
        result['error'] = 'Not found: ' + easyrsa
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    easyrsacmd = easyrsa + ' --vars='+ cadir +'/easyrsa3/vars --pki='+ cadir +'/pki'
    p = pexpect.spawn(easyrsacmd + ' --days=90 --subject-alt-name=DNS:' + cn + ' gen-req ' + cn + ' nopass')
    if logger.level == 10:
        p.logfile = sys.stdout.buffer

    #output = p.read()
    output = ''
    i = p.expect(["Type the word 'yes' to continue, or any other input to abort.",
                  '.*Common Name \(eg: your user, host, or server name\).*',
                  pexpect.EOF])
    if i == 0:
        p.sendline('yes')
        logger.debug('confirmed certificate overwrite')
        p.expect('.*Common Name \(eg: your user, host, or server name\).*')
    elif i == 2:
        result['error'] = 'Failed to issue certificate: unexpected output'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        logger.error(output)
        return result

    p.sendline(cn)
    logger.debug('passed cn')
    p.expect('.*Private-Key and Public-Certificate-Request files created..*')

    logger.debug('key and csr created')
    p.kill(0)

    certreq = cadir + '/pki/reqs/' + cn + '.req'
    if os.path.isfile(certreq):
        logger.debug('csr file exists')
    else:
        result['error'] = 'Failed to create certificate request'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    keypath = cadir + '/pki/private/' + cn + '.key'
    if os.path.isfile(keypath):
        logger.debug('private key file exists')
        result['data'].append(keypath)
    else:
        result['error'] = 'Failed to create certificate private key'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    cmdstr = easyrsacmd + ' --subject-alt-name=DNS:'+ cn
    if ip:
        cmdstr += ',IP:'+ ip
    if ip6:
        cmdstr += ',IP:'+ ip6

    p = pexpect.spawn(cmdstr +' sign-req server ' + cn)
    if logger.level == 10:
        p.logfile = sys.stdout.buffer
    p.expect('.*Confirm request details: .*')
    p.sendline('yes')
    p.expect('.*Enter pass phrase for ' + cadir + '/pki/private/ca.key:')
    p.sendline(cakey)
    p.expect('.*Certificate created.*')
    p.kill(0)

    certpath = cadir + '/pki/issued/' + cn + '.crt'
    if os.path.isfile(certpath):
        logger.debug('certificate created')
        result['data'].append(certpath)
    else:
        result['error'] = 'Failed to create certificate'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])

    p = pexpect.spawn(easyrsacmd + ' gen-dh', timeout=180)
    if logger.level == 10:
        p.logfile = sys.stdout.buffer
    i = p.expect(['DH parameters of size 2048 created.*', '.*Overwrite?'])
    if i == 1:
        p.sendline('yes')
        p.expect('DH parameters of size 2048 created.*')

    p.kill(0)

    dhpath = cadir + '/pki/dh.pem'
    if os.path.isfile(dhpath):
        logger.debug('dh file exists')
        result['data'].append(dhpath)
    else:
        result['error'] = 'Failed to create DH parameters'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    status = reload_nginx()
    status['data'] = result['data']
    return status

def app_cert_renew():
    '''Renew the server certificate for the local HaxHQ instance. CN is haxhq.SENDER_DOMAIN'''
    result = {'success': False, 'error': None, 'data': []}
    logger.debug('Renewing server certificate for the local HaxHQ instance')

    app = Flask(__name__)
    app.config.from_object('def_settings')
    cakey = app.config['CA_KEY']
    cadir = app.config['CADIR']
    cn = 'haxhq.'+ app.config['SENDER_DOMAIN']

    easyrsa = cadir + '/easyrsa3/easyrsa'
    if not os.path.isfile(easyrsa):
        result['error'] = 'File not found: local CA directory might be wrong'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        logger.error('Not found: ' + easyrsa)
        return result

    easyrsacmd = easyrsa + ' --vars='+ cadir +'/easyrsa3/vars --pki='+ cadir +'/pki'

    if os.path.isfile(cadir + '/pki/renewed/issued/' + cn + '.crt'):
        logger.debug('Renewed cert exists, revoking')
        status = revoke_renewed(cn, reload=False)
        if not status['success']:
            return status
    else:
        # use the monthly certificate renewal to generate a new CRL.
        # It runs as part of revoke above or here
        status = generate_crl()
        if not status['success']:
            return status

    try:
        p = pexpect.spawn(easyrsacmd + ' --days=90 renew ' + cn)
        if logger.level == 10:
            p.logfile = sys.stdout.buffer
    except Exception as e:
        result['error'] = 'Failed to renew certificate'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        logger.error(e)
        return result

    i = p.expect(['.*Continue with renewal:', 'Missing certificate file:', 'Cannot renew this certificate, a conflicting file exists:'])
    if i == 1:
        result['error'] = 'Unable to renew as the certificate was not found'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result
    elif i == 2:
        result['error'] = 'Certificate already renewed and old certificate not yet revoked'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result

    p.sendline('yes')
    p.expect('Enter pass phrase for.*')
    p.sendline(cakey)
    i = p.expect(['Renew was successful.', 'Could not read CA private key.*'])
    if i == 1:
        result['error'] = 'Could not read CA private key'
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
        return result
    else:
        p.kill(0)
        logger.info('Renewed certificate for ' + cn)


    certpath = cadir + '/pki/issued/' + cn + '.crt'
    if os.path.isfile(certpath):
        if (time.time() - os.stat(certpath).st_mtime) > 30:
            # file should be generated just now, if it is older than 30 sec something is amiss
            result['error'] = 'Certificate file is older than expected, renewal error'
            logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
            return result
        else:
            result['success'] = True
            result['data'] = [certpath]
            logger.debug('.crt file created')
    else:
        result['error'] = 'Not found: ' + certpath
        logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])

    status = reload_nginx()
    status['data'] = result['data']
    return status

def get_login_logo():
    '''Returns the path to the image to be used as the logo on the login page'''
    result = {'success': False, 'error': None, 'data': []}
    logger.debug('getting login logo for the instance')

    qry = db_getrow('select login_logo_src, login_logo_width, login_logo_height from haxhq_settings')
    if qry['success']:
        if qry['data']:
            result['data'] = qry['data']
            result['success'] = True
        else:
            result['error'] = 'No login logo found'
            logerror(__name__, getframeinfo(currentframe()).lineno, result['error'])
    else:
        result['error'] = 'Failed to retrieve login logo: query error'
        logger.error(result['error'])

    return result

def update_login_logo(filepath):
    '''Set a new image for use as the logo on the login page'''
    result = {'success': False, 'error': None, 'data': []}
    logger.debug('updating login page logo to {}'.format(filepath))

    im = Image.open(filepath)
    width, height = im.size

    cols = ['login_logo_src', 'login_logo_width', 'login_logo_height']
    vals = [filepath, width, height]

    sql = get_pg_update_sql('haxhq_settings', cols, None)
    qry = db_do(sql, tuple(vals))

    result['success'] = qry['success']
    result['error'] = qry['error'] if 'error' in qry else None

    return result
