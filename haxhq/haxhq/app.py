import psycopg2
import logging
import pylibmc
import json
import re
import click
from os import path
from flask_session import Session
from datetime import date, datetime, timedelta
from flask import Flask, session, request, render_template, url_for, flash, redirect, jsonify, abort, send_from_directory, send_file, make_response
from flask_wtf.csrf import CSRFProtect
from urllib.parse import unquote_plus
from werkzeug.utils import secure_filename
from collections import namedtuple
from inspect import currentframe, getframeinfo
import xhq.engagement
import xhq.hacking
import xhq.library
import xhq.reporting
import xhq.forms
import xhq.mkdoc
import xhq.auth
import xhq.stats
import xhq.reports
import xhq.admin
from xhq.authorise_config import engagement_types, get_default_route
from xhq.auth import login_required
from xhq.util import get_db, logerror, mc, send_email, email_enabled

app = Flask(__name__)
app.config.from_object('def_settings')

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
sess = Session()
sess.init_app(app)

csrf = CSRFProtect()
csrf.init_app(app)

#stripe.api_key = app.config['STRIPE_DEV_KEY']

#mc = pylibmc.Client(["127.0.0.1"], binary=True, behaviors={"tcp_nodelay": True, "ketama": True})
logging.basicConfig(filename='../logs/haxhq.log',format='%(asctime)s %(filename)s [%(lineno)d] %(levelname)s:%(message)s')
logger = logging.getLogger(__name__)
logger.setLevel('INFO')
logger.setLevel('DEBUG')

def allowed_file(filename):
    logger.debug('checking file extension')
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.cli.command('initdb')
def initdb_command():
    """Initializes the database."""
    conn = get_db()
    curs = conn.cursor()
    with app.open_resource('schema.sql') as f:
        curs.execute(f.read())
    conn.commit()
    conn.close()
    print('Initialized the database.')

@app.cli.command('check_connectivity')
def check_connectivity_command():
    '''Checks if network settings allow python updates and sending email'''
    if xhq.admin.check_env():
        print('Checks completed successuly')

@app.cli.command('init_ca')
def init_ca_command():
    '''Initialise the integrated Certificate Authority'''
    status = xhq.admin.init_ca()
    if status['success']:
        print('HaxHQ Root CA initialised')
    else:
        print(status['error'])

@app.cli.command('enable_client_cert_auth')
def enable_client_cert_auth_command():
    '''Update nginx config to require and verify client certificates and reload it'''
    status = xhq.admin.enable_cert_auth()
    if status['success']:
        print('Client certificate authentication enabled')
    else:
        print(status['error'])

@app.cli.command('disable_client_cert_auth')
def disable_client_cert_auth_command():
    '''Update nginx config to stop requiring client certificates and reload it'''
    status = xhq.admin.disable_cert_auth()
    if status['success']:
        print('Client certificate authentication disabled')
    else:
        print(status['error'])

@app.cli.command('get_client_cert')
@click.option('--password', prompt='Please enter password: ', help='The password to encrypt the certificate with')
@click.argument('email')
def get_client_cert_command(email, password):
    '''Generate or renew (if required) client certificate and print path ot .p12 file'''
    status = xhq.admin.get_client_cert(email, password)
    if status['success']:
        print('Client certificate is at: ' + status['data'][0])
    else:
        print(status['error'])

@app.cli.command('issue_server_cert')
def issue_server_cert_command():
    '''Generate or renew (if required) a server certificate and private key'''
    status = xhq.admin.app_cert_issue()
    if status['success']:
        print('Server certificate issued')
    else:
        print(status['error'])

@app.cli.command('updatepass')
@click.option('--password', prompt='Please enter the new password', help='The password to set for the account')
@click.argument('email')
def updatepass_command(email, password):
    '''Updates an existing user's password'''
    if xhq.admin.update_pass(password, email=email):
        print('Password updated')

@app.route('/checktoken')
def checktoken():
    if 'logged_in' in session and session['logged_in']:
        logger.debug('session present')
        if 'email' in session and 'user_id' in session and 'user_groups' in session:
            redirect_to = get_default_route()
            logger.debug('user group is ' + session['user_groups'][0] + ' redirecting to ' + redirect_to)
            return redirect(url_for(redirect_to))
        else:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'partial session: ' + repr(session))

    # if the user is not fully logged in, reset/create a session on accessing the login or root page
    logger.debug('not logged in, adding empty session')
    xhq.auth.add_session()

    token = request.args.get('token')
    if token:
        logger.debug('attempting token auth')
        if xhq.auth.authenticate(token):
            data = {'subtitle': 'Token authenticated', 'user_groups': session['user_groups'], 'user': session['nickname']}
            return render_template('usetoken.j2', **data)
        elif session['tokenverified']:
            if session['otp_secret']:
                logger.debug('otp secret exists')
                return redirect(url_for('check_2fa'))
            elif session['mfa_required']:
                logger.debug('no otp secret stored but mfa is required: ' + repr(session['mfa_required']))
                return redirect(url_for('setup_mfa'))
        else:
            logger.debug('token auth failed')
            return redirect(url_for('login'))
    else:
        logger.debug('no token in request, redirecting to login')
        return redirect(url_for('login'))

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if xhq.auth.check_session():
            logger.debug('session present')
            redirect_to = get_default_route()
            logger.debug('user group is {} redirecting to {}'.format(session['user_groups'][0], redirect_to))
            return redirect(url_for(redirect_to))
        else:
            # if the user is not fully logged in, reset/create a session on accessing the login or root page
            #flask.Response.delete_cookie('haxhq_session')
            xhq.auth.add_session()

        form = xhq.forms.get_form('login')
        data = {'subtitle': 'Login', 'page': 'login', 'user_groups': []}
        if 'SENDER_DOMAIN' in app.config and app.config['SENDER_DOMAIN'] == 'haxhq.com':
            data['demo'] = True
        else:
            data['demo'] = False

            logo_dict = xhq.admin.get_login_logo()
            for k in logo_dict['data'].keys():
                data[k] = logo_dict['data'][k]

        return render_template('login.j2', **data, form=form)
    else:
        form = xhq.forms.get_form('login')
        if form.validate_on_submit():
            xhq.auth.authenticate()
            if session['logged_in']:
                logger.debug('successful authentication, user logged in: ' + repr(session['logged_in']))
                redirect_to = get_default_route()
                logger.debug('user group is ' + session['user_groups'][0] + ' redirecting to ' + redirect_to)
                return redirect(url_for(redirect_to))
            elif 'otp_secret' in session and session['otp_secret']:
                logger.debug('otp secret exists')
                return redirect(url_for('check_2fa'))
            elif 'mfa_required' in session and session['mfa_required']:
                logger.debug('no otp secret stored but mfa is required: ' + repr(session['mfa_required']))
                return redirect(url_for('setup_mfa'))
        else:
            if form.errors:
                for field, errors in form.errors.items():
                    for error in errors:
                        message = 'validation error in ' + field + ': ' + error
                        logger.info(message)
                        flash(message, 'error')

        flash('Authentication failed', 'error')
        return render_template('login.j2', form=form)

@app.route('/check_2fa', methods=['GET', 'POST'])
def check_2fa():
    if not (session['pass_checked'] or session['tokenverified']):
        logger.debug('2fa check without prior auth, rejecting')
        abort(401)

    data = {'subtitle': 'Login', 'user_groups': []}
    form = xhq.forms.get_form('2fa_check')
    if request.method == 'GET':
        return render_template('check_2fa.j2', **data, form=form)
    else:
        if form.validate_on_submit():
            user = xhq.auth.check_2fa()
            if user:
                logger.info('2fa check successful: ' + session['email'])
                xhq.auth.login(user)
                redirect_to = 'usersettings' if session['tokenverified'] else get_default_route()
                logger.debug('user group is ' + session['user_groups'][0] + ' redirecting to ' + redirect_to)
                return redirect(url_for(redirect_to))
            else:
                flash('Bad OTP code, please try again', 'error')
                logging.warn('2fa check failed for user ' + session['email'])
        else:
            if form.errors:
                for field, errors in form.errors.items():
                    for error in errors:
                        message = 'validation error in ' + field + ': ' + error
                        logger.info(message)
                        flash(message, 'error')

    return render_template('check_2fa.j2', **data, form=form)

@app.route('/disable_2fa', methods=['POST'])
@login_required
def disable_2fa():
    form = xhq.forms.get_form('2fa_check')
    if form.validate_on_submit():
        logger.debug('otp form data is valid')
        if xhq.auth.check_2fa():
            logger.debug('2FA otp_code verified, disabling 2fa')
            if xhq.admin.disable_2fa():
                flash('2FA disabled', 'info')
                return redirect(url_for('usersettings'))
        else:
            logger.debug('incorrect 2fa code submitted')
            flash('Incorrect 2FA code, please try again', 'error')
    else:
        logger.debug('invalid otp code, form validation failed')
        flash('Invalid OTP code, 6 digits expected', 'error')

    return redirect(url_for('usersettings'))

@app.route('/setup_mfa', methods=['GET', 'POST'])
def setup_mfa():
    if not (session['pass_checked'] or session['tokenverified'] or session['logged_in']):
        logger.debug('unauthenticated access to setup_mfa route')
        abort(401)

    if 'qr_img' in session and session['qr_img'] and 'otp_secret' in session and session['otp_secret']:
        logger.debug('using stored mfa setup data')
        data = {'subtitle': 'Enable two-factor authentication', 'user_groups': [], 'img': session['qr_img'],
                'secret': session['otp_secret'], 'email_enabled': email_enabled()}
    else:
        logger.debug(repr(session))
        logger.debug('creating new opt secret and qr image')
        data = xhq.auth.setup_mfa()
        if not data:
            # for resetting MFA, the dedicated route should be used as that verifies access to the existing one
            logger.warn('setup_mfa route used when mfa already enabled')
            abort(401)

    form = xhq.forms.get_form('2fa_check')
    if request.method == 'POST':
        logger.debug('otp_code submitted')
        if form.validate_on_submit():
            logger.debug('otp form data is valid')
            if xhq.auth.check_2fa():
                logger.debug('2FA otp_code verified, saving new otp_secret')
                flash('MFA successfully set up', 'info')
                user = xhq.auth.setup_mfa(save=True)
                if user:
                    logger.debug('secret saved, logging the user in')
                    xhq.auth.login(user)
                logger.debug('user group is ' + session['user_groups'][0])
                redirect_to = 'usersettings' if session['tokenverified'] else get_default_route()
                logger.debug('redirecting to ' + redirect_to)
                return redirect(url_for(redirect_to))
            else:
                flash('wrong code, please try again', 'error')
                logging.info('wrong otp code submitted')
        else:
            if form.errors:
                for field, errors in form.errors.items():
                    for error in errors:
                        message = 'validation error in ' + field + ': ' + error
                        logger.info(message)
                        flash(message, 'error')

    return render_template('setup_mfa.j2', **data, form=form)

@app.route('/enable_2fa')
@login_required
def enable_2fa():
    form = xhq.forms.get_form('2fa_check')
    data = xhq.auth.setup_mfa()
    data = data | {'subtitle': 'Enable 2FA', 'user': session['nickname'],
                   'user_groups': session['user_groups'], 'has_stats': session['has_stats']}
    if not data:
        # for resetting MFA, the dedicated route should be used as that verifies access to the existing one
        logger.warn('setup_mfa route used when mfa already enabled')
        abort(401)

    return render_template('setup_mfa.j2', **data, form=form)

@app.route('/logout')
def logout():
    if xhq.auth.logout():
        data = {'subtitle': 'Login', 'page': 'login', 'user_groups': []}
        if 'SENDER_DOMAIN' in app.config and app.config['SENDER_DOMAIN'] == 'haxhq.com':
            data['demo'] = True
        else:
            data['demo'] = False

            logo_dict = xhq.admin.get_login_logo()
            for k in logo_dict['data'].keys():
                data[k] = logo_dict['data'][k]

        form = xhq.forms.get_form('login')

        resp = make_response(render_template('login.j2', **data, form=form))
        resp.set_cookie('sessionID', '', expires=0)
        return resp
    else:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'Logout fail')
        return redirect(request.referrer)

@app.route('/reset_pass', methods=['GET', 'POST'])
def reset_pass():
    if 'SENDER_DOMAIN' in app.config and app.config['SENDER_DOMAIN'] == 'haxhq.com':
        demo = True
    else:
        demo = False

    data = {'subtitle': 'Reset password', 'page': 'reset_pass', 'user_groups': [], 'email_enabled': email_enabled(), 'demo': demo}
    form = xhq.forms.get_form('reset_pass')
    if request.method == 'GET':
        return render_template('reset_pass.j2', **data, form=form)
    else:
        if form.validate_on_submit():
            user = request.form['user']
            status = xhq.auth.reset_pass(user)
            if status['success']:
                flash('If the user exists, a password reset email has been sent', 'info')
            else:
                logger.warn('failed to send reset email: ' + status['error'])
                flash(status['error'], 'error')
        else:
            if form.errors:
                for field, errors in form.errors.items():
                    for error in errors:
                        message = 'validation error in ' + field + ': ' + error
                        logger.info(message)
                        flash(message, 'error')

        return render_template('reset_pass.j2', **data, form=form)

@app.route('/engagement', methods=['GET', 'POST'])
@login_required
def engagement():
    form = xhq.forms.get_form('new_engagement')
    user_groups = session['user_groups']
    #for group in user_groups:
    #    for choice in engagement_types[group]:
    #        form.test_type.choices.append(choice)

    #if len(form.test_type.choices) == 1:
    #    _test_type = form.test_type.choices[0][0]
    #    form.test_type.render_kw = {'class': 'form_right hidden'}

    if 'hackers' not in user_groups:
        del form.test_type

    data = xhq.engagement.get_vars()
    if 'error' in data:
        flash('error determining active engagement, please activate one to resolve', 'error')
        return render_template('engagement.j2', **data, form=form)

    if request.method == 'POST':
        if form.validate_on_submit():
            logger.debug('engagement form validated')
            if xhq.engagement.save_form():
                flash('Engagement created', 'info')
                data = xhq.engagement.get_vars()
                return redirect(url_for('engagement'))
            else:
                flash('Error creating engagement', 'error')
        else:
            logger.debug('engagement form failed to validate')
            if form.errors:
                for field, errors in form.errors.items():
                    for error in errors:
                        message = 'validation error in ' + field + ': ' + error
                        logger.info(message)
                        flash(message, 'error')

    return render_template('engagement.j2', **data, form=form)

@app.route('/dummy_eng')
@login_required
def dummy_eng():
    logger.debug('creating a dummy engagement')
    eng_type = request.args.get('eng_type')
    if not xhq.engagement.create_dummy(eng_type):
        flash('Error creating dummy engagement', 'error')

    return redirect(url_for('engagement'))

@app.route('/hacking/<hid>', methods=['GET', 'POST'])
@login_required
def hacking(hid):
    if request.method == 'POST':
        if hid == 'filter':
            filterform = xhq.forms.get_form('hostfilter')
            form = xhq.forms.get_form('upload_file')
            # preserve the content of the filter form, even if it doesn't validate
            obj = None
            params = { param:value for (param, value) in request.form.items() if value }
            del params['csrf_token']
            if params:
                fdata = tuple(params.values())
                FormData = namedtuple('FormData', ', '.join(params.keys()))
                obj = FormData._make(fdata)

            if filterform.validate_on_submit():
                res = xhq.hacking.get_vars({'view': 'filter'})
                logger.debug('got filtered data: ' + str(len(res['data'])))
                filterform = xhq.forms.get_form('hostfilter', obj=obj)
                return render_template('hacking.j2', **res, form=form, filterform=filterform)
            else:
                logger.debug('host filter form failed to validate')
                if filterform.errors:
                    for field, errors in filterform.errors.items():
                        for error in errors:
                            message = 'validation error in ' + field + ': ' + error
                            logger.info(message)
                            flash(message, 'error')

                filterform = xhq.forms.get_form('hostfilter', obj=obj)
                res = xhq.hacking.get_vars({'view': 'main'})
                return render_template('hacking.j2', **res, form=form, filterform=filterform)
        else:
            logger.info('unexpected post request')
            return redirect(url_for('hacking', hid='main'))
    else:
        if re.match('^\d+$', hid):
            data = xhq.hacking.get_vars({ 'view': 'host', 'hid': hid })
            if not data['host']:
                return redirect(url_for('hacking', hid='main'))

            return render_template('showhost.j2', **data)
        elif hid == 'main':
            data = xhq.hacking.get_vars({'view': 'main'})
            form = xhq.forms.get_form('upload_file')
            filterform = xhq.forms.get_form('hostfilter')

            msgkey = 'messages_' + str(session['user_id'])
            if msgkey in mc:
                logger.debug(msgkey + ' present in mc')
                messages = mc[msgkey].strip('##').split('##')
                if messages:
                    for msg in messages:
                        if msg:
                            logger.debug('flashing: ' + msg)
                            flash(msg, 'error')
                mc[msgkey] = ''

            prockey = 'processing_' + str(session['user_id'])
            if prockey in mc:
                logger.info('clearing stale processing flag: ' + repr(mc[prockey]))
                mc[prockey] = False


            return render_template('hacking.j2', **data, form=form, filterform=filterform)
        else:
            logger.info('bad host id: {}'.format(hid))
            abort(404)

@app.route('/reporting/<iid>', methods=['GET', 'POST'])
@login_required
def reporting(iid):
    if not (iid == 'all' or re.match('^\d+$', iid)):
        logger.info('bad issue id: {}'.format(iid))
        abort(404)

    if request.method == 'GET':
        data = xhq.reporting.get_vars(iid)
        if iid == 'all':
            form = xhq.forms.get_form('dummy')
            return render_template('reporting.j2', **data, form=form)
        else:
            if not data['success']:
                logger.error('failed to get vars for reporting page')
                return redirect(url_for('reporting', iid='all'))

            reloadlib = request.args.get('reloadlib')
            issue, metadata = xhq.reporting.get_issue(iid, reloadlib=reloadlib)
            #logger.debug(repr(issue))
            data = data | metadata
            hform = xhq.forms.get_form('add_host')
            if data['eng_type'] == 'audit':
                form = xhq.forms.get_form('edit_csa_issue', obj=issue)
            else:
                form = xhq.forms.get_form('edit_issue', obj=issue)

            return render_template('editissue.j2', **data, form=form, hform=hform)

    elif request.method == 'POST':
        logger.debug(repr(request.form))
        if 'rationale' in request.form:
            form = xhq.forms.get_form('edit_csa_issue')
        else:
            form = xhq.forms.get_form('edit_issue')

        if ('cmd' in request.form and request.form['cmd'] == 'delrep'):
            if re.match('^\d{1,6}$', request.form['iid']):
                result = xhq.reporting.save_issue()
            else:
                logger.debug('invalid issue id: ' + str(request.form['iid']))
                result['error'] = 'Invalid issue id'

        elif form.validate_on_submit():
            logger.debug('issue form validated')
            result = xhq.reporting.save_issue()
        else:
            if form.errors:
                logger.debug('failed to validate form')
                for field, errors in form.errors.items():
                    for error in errors:
                        msg = 'validation error in ' + field + ': ' + error
                        logger.debug(msg)
                        flash(msg, 'error')

                return redirect(url_for('reporting', iid=iid))

        if result['error']:
            flash(result['error'], 'error')
        else:
            logger.debug('redirecting to ' + result['url'])
            return redirect(result['url'])


        return redirect(url_for('reporting', iid=iid))

@app.route('/get_merges/<iid>')
@login_required
def get_merges(iid):
    if re.match('^\d+$', iid):
        form = xhq.forms.get_form('dummy')
        data = xhq.reporting.suggest_merge_delete(iid)
        if data:
            return render_template('check_merge_suggestions.j2', **data, form=form)
        else:
            flash('no merge suggestions', 'error')
    else:
        logger.debug('bad issue id {}'.format(iid))
        return abort(404)


@app.route('/merge_issues/<iid>', methods=['POST'])
@login_required
def merge_issues(iid):
    if re.match('^\d+$', iid):
        if xhq.reporting.merge_issues(iid):
            return redirect(url_for('reporting', iid='all'))
        else:
            return redirect(url_for('reporting', iid='all'))
    else:
        logger.debug('bad issue id {}'.format(iid))
        return abort(404)

@app.route('/add_host/<iid>', methods=['POST'])
@login_required
def add_host(iid):
    if not re.match('^\d+$', iid):
        logger.debug('bad issue id {}'.format(iid))
        return abort(404)

    logger.debug('adding host to issue {}'.format(iid))
    form = xhq.forms.get_form('add_host')
    if form.validate_on_submit():
        logger.debug('engagement form validated')
        status = xhq.reporting.add_issue_host(iid)
        if status['errors']:
            for error in status['errors']:
                flash(error, 'error')
    else:
        logger.debug('engagement form failed to validate')
        if form.errors:
            for field, errors in form.errors.items():
                for error in errors:
                    message = 'validation error in ' + field + ': ' + error
                    logger.info(message)
                    flash(message, 'error')


    return redirect(url_for('reporting', iid=iid))

@app.route('/add_issue', methods=['GET', 'POST'])
@login_required
def add_issue():
    data = {'page': 'reporting', 'hidden_fields': ['CSRF Token'], 'user_groups': session['user_groups'], 'user': session['nickname'],
            'subtitle': 'Add finding', 'isadmin': session['isadmin'],  'has_stats': xhq.auth.authorise_access('stats')}

    form = xhq.forms.get_form('add_issue')
    hform = xhq.forms.get_form('add_host')

    if request.method == 'POST':
        if hform.validate_on_submit():
            logger.debug('hform validated')
            if form.validate_on_submit():
                logger.debug('form validated')

                result = xhq.reporting.add_issue()
                if result['success']:
                    if result['status'] == 'saved2library':
                        flash('Issue saved to library', 'info')
                        #TODO load saved issue from lib, need to add host data too
                    elif result['status'] == 'saved2report':
                        return redirect(url_for('reporting', iid='all'))
                else:
                    for error in result['errors']:
                        flash(error, 'error')
            else:
                logger.debug('form failed validation')
                if form.errors:
                    for field, errors in form.errors.items():
                        for error in errors:
                            message = 'validation error in ' + field + ': ' + error
                            logger.info(message)
                            flash(message, 'error')
        else:
            logger.debug('hform failed validation')
            if hform.errors:
                for field, errors in hform.errors.items():
                    for error in errors:
                        message = 'validation error in ' + field + ': ' + error
                        logger.info(message)
                        flash(message, 'error')

    return render_template('add-issue.j2', form=form, hform=hform, **data)

@app.route('/autoupdate_issues')
@login_required
def autoupdate_issues():
    if xhq.reporting.autoupdate_issues():
        return redirect(url_for('reporting', iid='all'))
    else:
        flash('Error importing library data', 'error')

@app.route('/generate_report')
@login_required
def generate_report():
    user_id = session['user_id']
    reportby = request.args.get('reportby')
    result = xhq.mkdoc.create_report(user_id, reportby)
    if result['success']:
        return send_from_directory(app.config['REPORT_FOLDER'], result['filename'], as_attachment=True)
    else:
        flash(result['error'])
        return redirect(url_for('reporting', iid='all'))

@app.route('/export_xlsx')
@login_required
def export_xlsx():
    filename = xhq.mkdoc.create_xlsx()
    return send_from_directory(app.config['REPORT_FOLDER'], filename, as_attachment=True)

@app.route('/export_iplist')
@login_required
def export_iplist():
    txtfile = xhq.hacking.get_iplist_txt(request.args)
    return send_file(txtfile, as_attachment=True, download_name='iplist.txt', mimetype='text/plain')

@app.route('/activate/<eid>')
@login_required
def activate(eid):
    if not re.match('^\d+$', eid):
        logger.debug('bad engagement id {}'.format(eid))
        return abort(404)

    result = {'success': False}
    result = xhq.engagement.activate(eid)
    logger.debug(repr(result))

    if result['success']:
        return redirect(url_for('engagement'))
    else:
        flash('Error activating engagement', 'error')

@app.route('/summarise_findings')
@login_required
def summarise_findings():
    drop_existing = request.args.get('drop_existing')
    if drop_existing:
        xhq.reporting.clear_summary()

    if xhq.reporting.summarise_findings():
        return redirect(url_for('reporting', iid='all'))
    else:
        return 'failed to summarise findings'

@app.route('/get/<what>', methods=['GET', 'POST'])
@login_required
def get(what):
    result = {}
    if what == 'vulnserv_details':
        # pass service_id, vuln_id and return plugin_output, proof etc
        pass
    elif what == 'titlelist':
        # returns titles of issues in library which contain term
        term = unquote_plus(request.args.get('term'))
        _type = unquote_plus(request.args.get('type')) if 'type' in request.args else None
        result = xhq.library.get_titlelist(term, _type)

    elif what == 'lib_issue':
        lid = request.args.get('lid')
        title = request.args.get('title')
        if title:
            title = unquote_plus(title)
            exposure = request.args.get('exposure')

        result = xhq.library.get_lib_issue(title=title, lid=lid, exposure=exposure)

    elif what == 'suggestion':
        # pass vuln title, report field (e.g. impact) and return stored texts for it
        # title itself may need to be modified
        # in issues table name is the original title, 'title' is the edited one to go into report
        name = unquote_plus(request.args.get('name')) if request.method == 'GET' else request.args.get('name')
        result = xhq.reporting.get_suggestions(name)

    elif what == 'hostlist':
        args = { arg: unquote_plus(request.args.get(arg)) for arg in request.args }
        args['main'] = 'host'
        result = xhq.hacking.get_hostlist(args)

    elif what == 'portlist':
        args = { arg: unquote_plus(request.args.get(arg)) for arg in request.args }
        args['main'] = 'port'
        result = xhq.hacking.get_portlist(args)

    elif what == 'servicelist':
        args = { arg: unquote_plus(request.args.get(arg)) for arg in request.args }
        args['main'] = 'service'
        result = xhq.hacking.get_servicelist(args)

    elif what == 'softwarelist':
        args = { arg: unquote_plus(request.args.get(arg)) for arg in request.args }
        args['main'] = 'software'
        result = xhq.hacking.get_softwarelist(args)

    elif what == 'vulnlist':
        args = { arg: unquote_plus(request.args.get(arg)) for arg in request.args }
        args['main'] = 'findings'
        result = xhq.hacking.get_vulnlist(args)

    elif what == 'stat_titlelist':
        term = unquote_plus(request.args.get('term'))
        result = xhq.stats.get_titlelist(term)
    elif what == 'exploitabilitylist':
        term = unquote_plus(request.args.get('term'))
        result = xhq.reporting.get_exploitabilitylist(term)
    elif what == 'discoverabilitylist':
        term = unquote_plus(request.args.get('term'))
        result = xhq.reporting.get_discoverabilitylist(term)
    else:
        logger.debug('bad parameter: {}'.format(what))
        return abort(404)

    return json.dumps(result)

@app.route('/del_issue_host')
@login_required
def del_issue_host():
    iid = request.args.get('issue_id')
    sid = request.args.get('sid')
    if not re.match('^\d+$', iid):
        logger.debug('bad issue id {}'.format(iid))
        return abort(404)

    if not re.match('^\d+$', sid):
        logger.debug('bad sid {}'.format(sid))
        return abort(404)

    if xhq.reporting.del_issue_host(iid, sid=sid):
        return redirect(url_for('reporting', iid = iid))
    else:
        flash('Error deleting host', 'error')
        return redirect(url_for('reporting', iid = iid))

@app.route('/delete_engagement')
@login_required
def delete_engagement():
    eid = request.args.get('eid')

    if not re.match('^\d+$', eid):
        logger.debug('bad id {}'.format(eid))
        return abort(404)

    if xhq.engagement.delete(eid):
        return redirect(url_for('engagement'))
    else:
        flash('Error deleting engagement', 'error')
        form = xhq.forms.get_form('new_engagement')
        data = xhq.engagement.get_vars()
        return render_template('engagement.j2', **data, form=form)

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if 'scanfile' not in request.files:
        flash('No file sent', 'error')
        logger.debug(repr(request.files))
        return redirect(url_for('hacking', hid='main'))

    prockey = 'processing_' + str(session['user_id'])
    msgkey = 'messages_' + str(session['user_id'])
    scanfiles = request.files.getlist('scanfile')
    #logger.debug(repr(request.form))
    for scanfile in scanfiles:
        if scanfile.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('hacking', hid='main'))

        if allowed_file(scanfile.filename):
            logger.info('importing ' + scanfile.filename + ': filename extension ok')
            filename = secure_filename(scanfile.filename)
            logger.debug('filename passed secure_filename check')
            filepath = path.join(app.config['UPLOAD_FOLDER'], filename)
            scanfile.save(filepath)
            logger.info('file saved')

            result = xhq.hacking.queue_import(filename, filepath, request.form['filecount'], mc)
            logger.debug(json.dumps(result))
        else:
            logger.info('ignoring upload request for unsupported file type: ' + scanfile.filename)
            result = {'error': 'Bad file extension. Acceptable extensions are: .xml, .nessus, .html, .txt'}
            flash('Ignored unsupported file type (' + scanfile.filename + ')', 'error')
            #return redirect(url_for('hacking', hid='main'))

    return json.dumps(result)

@app.route('/delete_scan')
@login_required
def delete_scan():
    scan_id = request.args.get('scan_id')
    # sanitised in hacking.delete_scan

    if xhq.hacking.delete_scan(scan_id):
        logger.debug('scan deleted: ' + str(scan_id))
        return redirect(url_for('hacking', hid='main'))
    else:
        flash('Error deleting scan', 'error')
        return redirect(url_for('hacking', hid='main'))

#@app.route('/stats')
#@login_required
#def stats():
#    if request.args:
#        fdata = tuple([ request.args[k] for k in ['title', 'exposure', 'stat_from', 'stat_to', 'results', 'orderby'] ])
#
#        FormData = namedtuple('FormData', 'title, exposure, stat_from, stat_to, results, orderby')
#        obj = FormData._make(fdata)
#        form = xhq.forms.get_form('stats', obj=obj)
#    else:
#        form = xhq.forms.get_form('stats')
#
#    status, data = xhq.stats.get_vulnstats()
#    if status['error']:
#        flash('Failed to retrieve stats', 'error')
#        return render_template('stats.j2', form=form)
#
#    return render_template('stats.j2', **data, form=form)

#@app.route('/reports', methods=['GET', 'POST'])
#@login_required
#def reports():
#    if request.method == 'POST':
#        filename = xhq.reports.generate_internal_report(request.form['rep_from'], request.form['rep_to'])
#        if filename:
#            logger.debug('file generated, sending ' + filename + ' from ' + app.config['REPORT_FOLDER'])
#            return send_from_directory(app.config['REPORT_FOLDER'], filename, as_attachment=True)
#        else:
#            flash('No matching engagements were found in the selected period', 'info')
#
#    today = date.today()
#    lastweek = today + timedelta(-7)
#    fdata = (lastweek.strftime("%d/%m/%Y"), today.strftime("%d/%m/%Y"))
#
#    FormData = namedtuple('FormData', 'rep_from, rep_to')
#    obj = FormData._make(fdata)
#    form = xhq.forms.get_form('reports', obj=obj)
#
#    status, data = xhq.reports.get_vars()
#    if status['error']:
#        flash('Failed to load reports page data', 'error')
#        return render_template('reports.j2', form=form)
#    else:
#        return render_template('reports.j2', **data, form=form)

@app.route('/library', methods=['GET', 'POST'])
@login_required
def library():
    if request.method == 'GET':
        data = xhq.library.get_data(args=request.args)

        if request.args:
            fdata = tuple([ request.args[k] for k in ['libsearchtype', 'libsearchstr'] ])
            FormData = namedtuple('FormData', 'libsearchtype, libsearchstr')
            obj = FormData._make(fdata)
            searchform = xhq.forms.get_form('libsearch', obj=obj)
        else:
            searchform = xhq.forms.get_form('libsearch')

        form = xhq.forms.get_form('add_issue')
        del form['details']
        logger.debug(repr(data))
        return render_template('library.j2', **data, form=form, searchform=searchform)
    else:
        editissueform = xhq.forms.get_form('add_issue')
        if editissueform.validate_on_submit():
            logger.debug('form validated')
            cmd = request.form['cmd'] if 'cmd' in request.form else None
            logger.debug(repr(request.form))
            status = xhq.library.save(request.form)
            if status['error']:
                flash(status['error'], 'error')
            else:
                if cmd == 'dellib':
                    flash('Library entry deleted', 'info')
                else:
                    flash('Library entry saved', 'info')

            if 'repiid' in request.form and cmd == 'savereplib':
                logger.debug('saved to library, redirecting to issue ' + str(request.form['repiid']))
                redirectto = url_for('reporting', iid=request.form['repiid'], reloadlib=True)
            else:
                logger.debug('no repiid ' + repr(request.form))
                redirectto = request.referrer

        else:
            logger.debug('edit issue form failed validation')
            if editissueform.errors:
                for field, errors in editissueform.errors.items():
                    for error in errors:
                        message = 'validation error in ' + field + ': ' + error
                        logger.info(message)
                        flash(message, 'error')

            redirectto = url_for('library')

        return redirect(redirectto)

@app.route('/usersettings', methods=['GET', 'POST'])
@login_required
def usersettings():
    if request.method == 'GET':
        data = xhq.admin.get_vars('usersettings')

        data['tokenverified'] = session['tokenverified']
        passwdform = xhq.forms.get_form('set_pass') if session['tokenverified'] else xhq.forms.get_form('update_pass')

        FormData = namedtuple('FormData', 'nickname')
        obj = FormData._make(tuple([session['nickname']]))
        nickform = xhq.forms.get_form('update_nickname', obj=obj)

        check_2fa_form = xhq.forms.get_form('2fa_check') if session['mfa_enabled'] and not session['mfa_required'] else None

        certpassform = xhq.forms.get_form('set_pass')
        return render_template('usersettings.j2', **data, passwdform=passwdform, nickform=nickform,
                               check_2fa_form=check_2fa_form, certpassform=certpassform)
    else:
        if xhq.admin.updateuser():
            logger.debug('Settings updated')
        else:
            logger.debug('Error updating settings. Please try again.')

        return redirect(url_for('usersettings'))

@app.route('/admin')
@login_required
def admin():
    logger.debug('Checking certificate related headers')
    cert_rem_data = request.headers.getlist("X-SSL-Client-Remain")
    if cert_rem_data:
        session['cert_remaining'] = cert_rem_data[0].strip('\\')
        logger.debug('Client certificate valid for another ' + str(session['cert_remaining']) + ' days')
    else:
        logger.debug('No X-SSL-Client-Remain header found')

    data = xhq.admin.get_vars('admin')
    adduserform = xhq.forms.get_form('adduser')
    settemplateform = xhq.forms.get_form('set_template')
    gettemplateform = xhq.forms.get_form('get_template')
    updatelogoform = xhq.forms.get_form('update_logo')

    return render_template('administration.j2', **data, adduserform=adduserform,
                                                        updatelogoform=updatelogoform,
                                                        settemplateform=settemplateform,
                                                        gettemplateform=gettemplateform)

@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if request.method == 'GET':
        #TODO hiding labels probably best done with a custom parameter in forms.py
        hidden_labels = ['CSRF Token', 'Save']
        if 'user_id' in request.args:
            # editing user, get user details and return populated form
            user_id = request.args.get('user_id')
            data = xhq.admin.getuser(user_id)
            if data:
                logger.debug('returning user data for uid ' + str(data['user_id']))
                FormData = namedtuple('FormData', tuple(data.keys()))
                obj = FormData._make(tuple(data.values()))
                form = xhq.forms.get_form('adduser', obj=obj)
                return render_template('userform.j2', hidden_labels=hidden_labels, form=form)
            else:
                # error or uid modified and user not found
                logerror(__name__, getframeinfo(currentframe()).lineno, 'user not found for user_id ' + str(user_id))
                flash('User not found. This is probably an error, please contact support', 'error')
        else:
            # adding user
            form = xhq.forms.get_form('adduser')
            del form.user_id
            return render_template('userform.j2', form=form, hidden_labels=hidden_labels)
    else:
        form = xhq.forms.get_form('adduser')
        if form.validate_on_submit():
            result = xhq.admin.saveuser(request.form)
            logger.debug(repr(result))
            if result['errors']:
                for error in result['errors']:
                    flash(error, 'error')
        else:
            if form.errors:
                for field, errors in form.errors.items():
                    for error in errors:
                        message = 'validation error in ' + field + ': ' + error
                        logger.info(message)
                        logger.debug(request.form[field])
                        flash(message, 'error')

    return redirect(url_for('admin'))

@app.route('/set_subscriber_mfa')
@login_required
def set_subscriber_mfa():
    if not xhq.admin.toggle_subscriber_mfa(session['customer_id']):
        flash('Failed to update MFA requirements, please contact support', 'error')

    return redirect(url_for('admin'))

@app.route('/get_template')
@login_required
def get_template():
    _args = request.args
    if 'template_type' in _args and 'template_version' in _args:
        customer_id = session['customer_id'] if 'customer_id' in session else None
        if not customer_id:
            flash('Bad session, please log in again', 'error')
            xhq.auth.logout()
            return redirect(url_for('login'))

        logger.debug('getting template filename')
        fullpath = xhq.admin.get_template(_args['template_type'], _args['template_version'], customer_id)
        if fullpath:
            template_file = path.basename(fullpath)
            logger.debug('template found, returning ' + template_file)
            return send_from_directory(app.config['TEMPLATE_FOLDER'], template_file, as_attachment=True)
        else:
            logerror(__name__, getframeinfo(currentframe()).lineno,
                     'Failed to get template file: ' + repr((_args['template_type'], _args['template_version'], customer_id)))
            flash('Error retrieving template file - please contact support.')

    else:
        logger.warn('incomplete arg set: ' + repr(_args))
        flash('Bad request - template type and/or version not specified', 'error')

    return redirect(url_for('admin'))

@app.route('/set_template', methods=['POST'])
@login_required
def set_template():
    customer_id = session['customer_id'] if 'customer_id' in session else None
    if not customer_id:
        flash('Bad session, please log in again', 'error')
        xhq.auth.logout()
        return redirect(url_for('login'))

    form = xhq.forms.get_form('set_template')
    if form.validate_on_submit():
        if 'template_file' not in request.files:
            flash('No file sent', 'error')
            logger.debug(repr(request.files))
            return redirect(url_for('admin'))

        # check template extension and save it to disk
        template_file = request.files['template_file']
        now = datetime.now().strftime('%H-%M-%S_%d-%m-%Y')
        filepath = ''
        if template_file.filename.endswith('.docx'):
            logger.info('importing ' + template_file.filename + ': filename extension ok')
            filename = secure_filename(template_file.filename)
            logger.debug('filename passed secure_filename check')
            m = re.search('(.*)__\d\d-\d\d-\d\d_\d\d-\d\d-\d\d\d\d.docx$', filename)
            filename = m[1] if m else filename[:-5]
            filename += '__' + now + '.docx'
            filepath = path.join(app.config['TEMPLATE_FOLDER'], filename)
            template_file.save(filepath)
            logger.info('file saved: ' + filename)
        else:
            logger.info('ignoring upload request for unsupported file type: ' + template_file.filename)
            flash('Bad file extension, only .docx templates are currently supported', 'error')
            return redirect(url_for('admin'))

        # install template for the engagement type and customer
        if 'template_type' in request.form:
            template_type = request.form['template_type']
            success = xhq.admin.set_template(filepath,template_type,customer_id)
            if success:
                flash(request.form['template_type'] + ' template updated', 'info')
            else:
                flash('Template update failed: ' + result['error'], 'error')
        else:
            logging.info('template type not specified in form data: ' + repr(request.form))
            flash('Request failed - bad form data', 'error')

        return redirect(url_for('admin'))
    else:
        if form.errors:
            for field, errors in form.errors.items():
                for error in errors:
                    message = 'validation error in ' + field + ': ' + error
                    logger.info(message)
                    flash(message, 'error')

        return redirect(url_for('admin'))

@app.route('/contact', methods=['POST'])
@login_required
def contact():
    subject = 'Support request from ' + session['email']
    message = request.form['message'] + '\n\n===session details===\n\n`' + repr(session)
    success = send_email('support@haxhq.com', subject, message, fromaddr = session['email'])
    if success:
        flash('Thank you for your email!', 'info')

    if request.referrer.startswith(request.base_url):
        redirectto = request.referrer
    else:
        logger.warn('unexpected referrer header: ' + request.referrer)
        redirectto = url_for('engagement')

    return redirect(redirectto)

@app.route('/colour_mode', methods=['GET'])
@login_required
def colour_mode():
    xhq.admin.toggle_colour_mode()
    return redirect(url_for('usersettings'))

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.config['FAVICON_FOLDER'], 'favicon.ico')

@app.route('/qrcode')
def qrcode():
    if session['logged_in'] or session['pass_checked'] or session['tokenverified']:
        filename = 'qr_' + str(session['user_id']) + '.png'
        folder = app.config['QRCODE_FOLDER'] + '/'
        logger.debug('serving ' + folder + filename)
        if not path.isfile(folder + filename):
            logger.error('qrcode file doesnt exist')

        return send_from_directory(app.config['QRCODE_FOLDER'], filename)
    else:
        logging.debug('refusing access to qrcode without pass, token or full session')
        abort(401)

@app.route('/register', methods=['POST'])
@csrf.exempt
def register():
    logger.info('regisering new demo user')
    result = xhq.admin.register()
    return json.dumps(result)

@app.route('/get_updates/<x>')
@login_required
def get_updates(x):
    if x in ['HaxHQ', 'Python', 'OS']:
        logger.debug('Checking for any available ' + x + ' updates')
        result = xhq.admin.get_updates(x)
        if result['success']:
            if result['data']:
                data = {'update_type': x, 'data': result['data']}
                return render_template('updates.j2', **data)
            else:
                msg = x if x == 'HaxHQ' else x + ' packages'
                msg += ' up to date.'
                return '<p class="green">' + msg + '</p>'
        else:
            msg = x if x == 'HaxHQ' else x + ' package'
            return '<p class="red">Failed to retrieve ' + msg + ' updates</p>'
    else:
        logger.warn('bad updates target: {}'.format(x))
        return abort(404)

@app.route('/update/<x>')
@login_required
def update(x):
    logger.info('Installing ' + x + ' updates')
    if x == 'HaxHQ':
        result = xhq.admin.update_hahxq()
    elif x == 'Python':
        result = xhq.admin.update_python()
    else:
        logger.warn('Unrecognised update request: ' + x)
        result = {'success': False, 'error': 'Unrecognised command'}

    return jsonify(result)

@app.route('/getlogs')
@login_required
def getlogs():
    # for SaaS instances this is not required
    if app.config['SHOWLOGS']:
        res = xhq.admin.collect_logs()
        if res['success']:
            if res['data']:
                result = jsonify(res['data'])
            else:
                result = jsonify(['No error or warning level logs found'])
        else:
            result = jsonify(['Error retrieving logs: ' + res['error']])
    else:
        result = jsonify(['To enable retrieving logs please set SHOWLOGS to True'])

    return result

@app.route('/get_cert', methods=['POST'])
@login_required
def get_cert():
    '''Return a valid .p12 file for the current user.
    If the current user doesn't have a certificate, generate one. If the user has a certificate, renew it.
    If the user has renewed before but not yet used the new certificate, generate the p12 from the current user's client certificate.'''
    email = session['email']
    logger.info('Retrieving client certificate for ' + email)
    form = xhq.forms.get_form('set_pass')
    if form.validate_on_submit():
        password = request.form['password1']
        if password == request.form['password2']:
            result = xhq.admin.get_client_cert(email, password)
            if result['success']:
                certfile = result['data'][0]
                logger.debug('returning ' + certfile)

                return send_from_directory(path.dirname(certfile), path.basename(certfile), as_attachment=True)
            else:
                logger.debug(repr(result))
                flash('Failed to get certificate: ' + result['error'], 'error')
        else:
            flash("The passwords didn't match, please try again", 'error')
    else:
        if form.errors:
            for field, errors in form.errors.items():
                for error in errors:
                    message = 'validation error in ' + field + ': ' + error
                    logger.info(message)
                    flash(message, 'error')

    return redirect(url_for('usersettings'))

@app.route('/disable_cert_auth')
@login_required
def disable_cert_auth():
    '''Disable client certificate authentication for this HaxHQ instance'''
    status = xhq.admin.disable_cert_auth()
    if status['success']:
        flash('Client certificate authentication disabled', 'info')
    else:
        flash(status['error'], 'error')

    return redirect(url_for('admin', reloadcertinfo=True))

@app.route('/enable_cert_auth')
@login_required
def enable_cert_auth():
    '''Enable client certificate authentication for this HaxHQ instance'''
    status = xhq.admin.enable_cert_auth()
    if status['success']:
        flash('Client certificate authentication enabled', 'info')
    else:
        flash(status['error'], 'error')

    return redirect(url_for('admin'))

@app.route('/update_login_logo', methods=['POST'])
@login_required
def update_login_logo():
    '''Update logo image on the login page'''

    form = xhq.forms.get_form('update_logo')
    if form.validate_on_submit():
        if 'logo_file' in request.files:
            logo_file = request.files['logo_file']
        else:
            flash('No file sent', 'error')
            logger.debug(repr(request.files))
            return redirect(url_for('admin'))

        if re.search('.jpg$|.jpeg$|.gif$|.png$|.webp$', logo_file.filename):
            logger.info('importing {}: filename extension ok'.format(logo_file.filename))
            filename = secure_filename(logo_file.filename)
            logger.debug('filename passed secure_filename check')
            filepath = path.join('static/img/', filename)
            logo_file.save(filepath)
            logger.info('file saved')
        else:
            flash('Accepted image extensions are .jpg, .jpeg, .gif, .png, .webp', 'error')
            logger.debug('bad logo image extension, rejecting')

        if 'SENDER_DOMAIN' in app.config and app.config['SENDER_DOMAIN'] == 'haxhq.com':
            logo_dict = xhq.admin.get_login_logo()
            if logo_dict['data']['login_logo_src'] == 'static/img/logo_white.png':
                status = xhq.admin.update_login_logo('static/img/hackercat_giphy.webp')
            else:
                status = xhq.admin.update_login_logo('static/img/logo_white.png')

            flash('This feature is restricted to static image change for this instance', 'info')
        else:
            status = xhq.admin.update_login_logo(filepath)

        if status['error']:
            flash('Logo update failed: {}'.format(status['error']), 'error')
            logger.error('failed to update login logo')
        else:
            flash('Login page logo updated', 'info')
            logger.debug('Logo updated successfully')

    return redirect(url_for('admin'))

#def err():
    #try:
    #    division_by_zero = 1 / 0
    #except Exception as e:
    #    logerror(__name__, getframeinfo(currentframe()).lineno, e)
#    return '<h1>Issue fixed 🎉<h1>'

