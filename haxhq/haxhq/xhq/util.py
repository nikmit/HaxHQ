import psycopg2
import psycopg2.extras
import smtplib
import logging
import socket
import string
import requests
import random
import hashlib
import pylibmc
import dns.asyncresolver
import io
import re
import ssl
from inspect import currentframe, getframeinfo
from flask import Flask, session
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.utils import formatdate, COMMASPACE
from email import encoders
from werkzeug.security import generate_password_hash

logger = logging.getLogger(__name__)
logger.setLevel('INFO')
#logger.setLevel('DEBUG')

mc = pylibmc.Client(["127.0.0.1"], binary=True, behaviors={"tcp_nodelay": True, "ketama": True})

def has_mx(fqdn):
    resolver = dns.resolver.Resolver()
    try:
        result = True if resolver.resolve(fqdn, 'MX')[0] else False
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        result = False
    except Exception as e:
        logger.warning('mx query failed in unexpected way')
        logger.warn(repr(e))
        result = False

    return result

def resolve(fqdn):
    result = {'ipv6': None, 'ipv4': None}
    for fam in [(socket.AF_INET6, '6'), (socket.AF_INET, '4')]:
        try:
            a = socket.getaddrinfo(fqdn, None, fam[0])
            result['ipv' + fam[1]] = a[0][4][0]
        except socket.error:
            pass
    return result

def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    app = Flask(__name__)
    app.config.from_object('def_settings')
    dbname = app.config['DB_NAME']
    dbpass = app.config['DB_PASS']
    dbuser = app.config['DB_USER']
    conn = psycopg2.connect(host='localhost', port='5432', dbname=dbname, user=dbuser, password=dbpass)
    conn.autocommit = False
    return conn


def db_do(sql, prm = None):
    result = {'success': True, 'data': None, 'errors': []}

    conn = get_db()
    curs = conn.cursor()

    sql = re.sub('\s+', ' ', sql)
    try:
        if prm:
            logger.debug("executing query: " + sql + ' ' + repr(prm))
            curs.execute(sql, prm)
        else:
            logger.debug("executing query: " + sql)
            curs.execute(sql)
    except psycopg2.Error as e:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'Failed to execute sql')
        # log the full error locally
        sqlstr = 'Failed to execute query: ' + sql % prm if prm else 'Failed to execute query: ' + sql
        logger.error(sqlstr)
        logger.error(e.pgerror)
        result['errors'].append('Failed to execute database query')
        result['success'] = False
        conn.close()

    if result['success']:
        if sql.lower().startswith('select'):
            try:
                result['data'] = curs.fetchall()
            except:
                pass
        else:
            try:
                result['data'] = curs.fetchone()[0]
            except Exception as e:
                #logerror(__name__, x.pgerror)
                pass

        conn.commit()
        conn.close()

    return result

def db_copy(array, table, columns, sep=',', null='None'):
    logger.debug('starting copy to ' + table + ' (' + repr(columns) + ') using separator: ' + sep)
#    logger.debug('creating copy_from file' + repr(array))
    f = io.StringIO('\n'.join(array))

    conn = get_db()
    curs = conn.cursor()
    curs.copy_from(f, table, sep=sep, null=null, columns=columns)
    conn.commit()
    conn.close()
    logger.debug('done copying data data to ' + table)

def copy_encode(data, separator):
    chars = ['#', '$', '|']
    replace_sep = False
    if separator in chars:
        chars.remove(separator)
        replace_sep = True

    nl = chars[0] + chars[0] + chars[1]
    sep = chars[1] + chars[1] + chars[0]
    eoc = chars[0] + chars[1] + chars[0]

    string = str(data).strip()
    encoded = re.sub(r'[\n\r]+', nl, string)
    encoded = re.sub(r'\\\.', eoc, encoded)

    if replace_sep:
        encoded = re.sub(re.escape(separator), sep, encoded)

    return encoded

def copy_decode(data, separator):
    #logger.debug('decoding ' + repr(data))
    #chars = ['#', '$', '|']
    #replace_sep = False
    #if separator in chars:
    #    chars.remove(separator)
    #    replace_sep = True
#
    #nl = chars[0] + chars[0] + chars[1]
    #sep = chars[1] + chars[1] + chars[0]

    #if replace_sep:
    #    decoded = re.sub(re.escape(sep), separator, data)
    #    decoded = re.sub(re.escape(nl), '\n', decoded)
    #else:
    #    decoded = re.sub(re.escape(nl), '\n', data)

    # replace 3 or more consecutive spaces with a single one - nessus texts have gaps in them
    decoded = re.sub(' {3,}', ' ', decoded)

    #logger.debug('decoded ' + repr(decoded))
    return decoded

def remove_repeat_whitespace(string):
    if isinstance(string, str):
        return ' '.join(string.split())
    else:
        logger.warn('non-string passed to remove_repeat_whitespace: ' + repr(string))
        return string

def db_getrow(sql, prm = None, multi = False):
    result = {'success': True, 'data': None, 'errors': []}

    conn = get_db()
    curs = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    try:
        if prm:
            curs.execute(sql, prm)
        else:
            curs.execute(sql)

    except Exception as e:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'Failed to execute sql')
        sqlstr = 'Failed to execute query: ' + sql % prm if prm else 'Failed to execute query: ' + sql
        logger.error(sqlstr)
        logger.error(e.pgerror)
        result['success'] = False
        result['errors'].append('Failed to execute database query')
    else:
        logger.debug(sql)
        logger.debug(prm)
        sqlstr = sql % prm if prm else sql
        logger.debug("executed query: " + sqlstr)

        data = curs.fetchall()
        conn.commit()
        conn.close()
        if multi:
            result['data'] = data
        else:
            if len(data) == 1:
                result['data'] = data[0]
            elif len(data) == 0:
                result['data'] = {}
            else:
                result['success'] = False
                result['errors'].append('Database query error')
                logerror(__name__, getframeinfo(currentframe()).lineno, 'More than one row returned from db_getrow without the multi flag')

    return result

def db_getdict(sql, prm = None) :
    return db_getrow(sql, prm, multi = True)

def db_getcol(sql, prm = None) :
    '''returns the column as a list'''
    result = db_do(sql, prm)
    if result['success']:
        if result['data']:
            data = result['data']
            if len(data[0]) == 1:
                result['data'] = list(list(zip(*data))[0])
            else:
                logerror(__name__, getframeinfo(currentframe()).lineno, 'db_getcol should only be used with queries returning a single column')
                logger.info(sql)
                result['success'] = False
                result['errors'].append('Database query error')
                result['data'] = None

    return result

def email_enabled():
    app = Flask(__name__)
    app.config.from_object('def_settings')
    if 'SMTP_PORT' in app.config and 'SMTP_SERVER' in app.config and 'SENDER_DOMAIN' in app.config:
        port = app.config['SMTP_PORT']
        host = app.config['SMTP_SERVER']
        sender_domain = app.config['SENDER_DOMAIN']
        if host and port and sender_domain:
            return True

    return False

def send_email(toaddr, subject, message, files=None, fromaddr=None):
    app = Flask(__name__)
    app.config.from_object('def_settings')
    port = app.config['SMTP_PORT']
    host = app.config['SMTP_SERVER']
    sender_domain = app.config['SENDER_DOMAIN']
    fromaddr = fromaddr if fromaddr else 'haxhq_instance@' + sender_domain

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    msg = MIMEMultipart() if files else MIMEText(message)

    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject
    msg['From'] = fromaddr
    msg['To'] = toaddr
    #msg['To'] = COMMASPACE.join(toaddr) if isinstance(toaddr, list) else toaddr

    if files:
        msg.attach(MIMEText(message))
        part = MIMEBase('application', "octet-stream")
        for f in files:
            with open(f, "rb") as fil:
                part.set_payload(fil.read())
            # After the file is closed
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename={}'.format(Path(f).name))
            msg.attach(part)

    #TODO this will break if toaddr is a list
    rcpt_domain = toaddr.split('@')[1]
    if has_mx(rcpt_domain):
        with smtplib.SMTP_SSL(host, port, context) as server:

            if 'SMTP_USER' in app.config and 'SMTP_PASS' in app.config:
                if app.config['SMTP_USER'] and app.config['SMTP_PASS']:
                    username = app.config['SMTP_USER']
                    password = app.config['SMTP_PASS']
                    try:
                        server.login(username, password)
                    except:
                        logger.info('Failed to send email - failed to authenticate to smtp server')
                        return { 'success': False, 'error': host + ' rejected the login credentials' }
                else:
                    logger.debug('no smtp credentials configured, attempting to send without authentication')
            else:
                logger.debug('SMTP_USER and SMTP_PASS missing from config, attempting to send without authentication')

            try :
                server.send_message(msg)
            except smtplib.SMTPRecipientsRefused :
                return { 'success': False,
                         'error': 'The ' + rcpt_domain + ' mail server rejected ' + toaddr + '. Did you mistype your email?' }
            except Exception as e:
                logger.warn('Failed to send email: ' + repr(e))
                return { 'success': False, 'error': 'Failed to send email - please try later' }
    else:
        return { 'success': False, 'error': 'Could not find mail server for domain ' + rcpt_domain }

    return { 'success': True }

def email_alert(subject, message=None) :
    send_email('nik@mitev.net', subject, message or subject)

def is_ip(address):
    for fam in [socket.AF_INET, socket.AF_INET6]:
        try:
            a = socket.inet_pton(fam, address)
            if len(a) == 16:
                return 6
            elif len(a) == 4:
                return 4
        except socket.error:
            pass

    logger.debug(address + ' is not a valid IP')
    return False

def randstring(size=6, chset = 'all'):
    letters = string.ascii_letters
    numbers = string.digits
    charset = { 'all': letters + numbers, 'letters': letters, 'numbers': numbers, 'wordsafe': 'bcdfghjklmnpqrstvwxz269' }
    return ''.join(random.choice(charset[chset]) for _ in range(size))

def get_longest_match(array):
    # passed a list of phrases, should return the longest match starting from word 1
    # e.g. ['Microsoft Windows 7', 'Microsoft Windows 10'] should return Microsoft Windows
    #TODO this could be improved to list e.g. Windows 7/10 or Linux Kernel 3.3-10
    #logger.debug('###' + repr(array))
    matches = []
    uniques = {}
    for entry in array:
        wordlist = entry.split(' ')
        pos = 1
        for word in wordlist:
            if not word:
                continue

            uniques.setdefault(pos, set()).add(word)
            pos += 1

    for position in range(1, len(uniques)+1):
        if len(uniques[position]) == 1:
            matches.append(uniques[position].pop())
        elif position > 1:
            #logger.info('### ' + ' '.join(matches))
            return ' '.join(matches)
        else:
            return False

def get_suffixed_number(num):
    suffixes = { '1': 'st', '2': 'nd', '3': 'rd'}
    last_digit = str(num)[-1]
    suffix = suffixes[last_digit] if last_digit in suffixes else 'th'
    return str(num) + suffix

def get_uniq_id(string):
    hashed = generate_password_hash(string)
    #throw away the salt value, just keep the hash
    return hashed.split('$')[-1]

def get_engagement_id(test_type=False):
    if test_type:
        qry = db_getrow('select eid, test_type from engagements where active is true and user_id = %s', (session['user_id'],))
        result = (str(qry['data']['eid']), qry['data']['test_type']) if qry['success'] else None
    else:
        qry = db_getcol('select eid from engagements where active is true and user_id = %s', (session['user_id'],))
        result = str(qry['data'][0]) if qry['success'] else None

    if not result:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'Failed to get engagement id')
    else:
        logger.debug('got eid: ' + repr(result) + ' for user ' + str(session['user_id']))

    return result

def logerror(module, lineno, error):
    app = Flask(__name__)
    app.config.from_object('def_settings')

    msg = module + ':' + str(lineno) + ': '
    msg += error if isinstance(error, str) else repr(error)

    #if 'SENTRY_DSN' in app.config:
    #    import sentry_sdk
    #    sentry_sdk.capture_message(msg)

    logger.error(msg)

def checklink(url):
    try:
        scode = requests.get(url).status_code
    except:
        scode = None

    if scode and scode == 200:
        return True
    else:
        return False

def get_fingerprint(issue):
    '''returns a hash of the .strip().lower() content of the following issue fields:
       'description', 'severity', 'cvss', 'cvss3', 'cve', 'remediation', 'impact', 'exploit_available'
       'exploitability_ease', 'see_also', 'patch_publication_date', 'rationale', 'reference', 'policy_value' '''

    tracked_fields = ['description', 'severity', 'cvss', 'cvss_vector', 'cvss3', 'cvss3_vector', 'cve', 'remediation', 'impact',
                      'exploit_available', 'exploitability_ease', 'see_also', 'patch_publication_date', 'rationale', 'reference',
                      'policy_value']

    issue_as_string = ''
    for fld in tracked_fields:
        if fld in issue and issue[fld]:
            string = issue[fld].strip().lower() if isinstance(issue[fld], str) else str(issue[fld])
            issue_as_string += string

    return hashlib.sha256(issue_as_string.encode()).hexdigest()

def get_pg_update_sql(table, cols, condition, trusted=False):
    if not trusted:
        if not re.match('[a-zA-Z_0-9]+$', table):
            logerror(__name__, getframeinfo(currentframe()).lineno, 'unsafe table name: ' + table)
            return False
        for col in cols:
            if not re.match('[a-zA-Z][a-zA-Z_0-9]+$', col):
                logerror(__name__, getframeinfo(currentframe()).lineno, 'unsafe column name: ' + col)
                return False

    sql = 'update ' + table + ' set '
    for i, col in enumerate(cols):
        sql += col + ' = %s ' if i+1 == len(cols) else col + ' = %s, '

    if condition:
        sql += condition

    return sql

def get_pg_insert_sql(table, cols, returning=None, trusted=None):
    if not trusted:
        if not re.match('[a-zA-Z_]+$', table):
            logerror(__name__, getframeinfo(currentframe()).lineno, 'unsafe table name: ' + table)
            return False
        for col in cols:
            if not re.match('[a-zA-Z][a-zA-Z_0-9]+$', col):
                logerror(__name__, getframeinfo(currentframe()).lineno, 'unsafe column name: ' + col)
                return False

    sql = 'insert into ' + table + '(' + ', '.join(cols) + ') values (' + '%s, '*(len(cols) - 1) + '%s)'
    if returning:
        sql += ' returning ' + returning

    return sql

def multiple_replace(_map, text):
  # Create a regular expression  from the dictionary keys
  regex = re.compile("(%s)" % "|".join(map(re.escape, _map.keys())))

  # For each match, look-up corresponding value in dictionary
  return regex.sub(lambda mo: _map[mo.string[mo.start():mo.end()]], text)

