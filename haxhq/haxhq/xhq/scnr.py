import re
import sys
import logging
import warnings
from bs4 import BeautifulSoup, SoupStrainer
from bs4 import MarkupResemblesLocatorWarning
from inspect import currentframe, getframeinfo
from defusedxml import ElementTree
from xhq.acunetix import parse_url
from xhq.netsparker import xhq_get_text
from xhq.util import is_ip, get_db, db_do, db_getcol, db_getrow, db_getdict, resolve, logerror, get_fingerprint, get_pg_update_sql, get_pg_insert_sql

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

logger = logging.getLogger(__name__)
logger.setLevel('DEBUG')

severity_map = {'high': 3, 'medium': 2, 'low': 1, 'informational': 0}

def parse(filename, eng_id):
    try:
        tree = ElementTree.parse(filename)
    except Exception as e:
        logger.error("Error: {}".format(e))
        return False

    root = tree.getroot()

    # get basic info about the target
    options = xhq_get_text(root.find('options'))
    scanned_url = options.split('\n')[-1]
    logger.debug('scanned url is {}'.format(scanned_url))

    if not scanned_url:
        logger.error('failed to get target url from options and sitemap')
        return False

    parsed_urls = {}
    if scanned_url not in parsed_urls:
        logger.debug('parsing url {}'.format(scanned_url))
        protocol, ip4, ip6, vhost, port = parse_url(scanned_url, eng_id)
        logger.debug('url parsed to: ' + repr((protocol, ip4, ip6, vhost, port)))
        parsed_urls[scanned_url] = [protocol, ip4, ip6, vhost, port]
    else:
        protocol, ip4, ip6, vhost, port = parsed_urls[scanned_url]

    res = {'scaninfo': {'ipv4': ip4, 'ipv6': ip6, 'hostname': vhost, 'proto': protocol, 'port': port, 'url': scanned_url}}

    hostandpath = scanned_url.split('://')[1]
    _elements = hostandpath.split('/')
    if len(_elements) > 2:
        # we have host.tld/path/path_or_cgi etc, set host.tld/path as webappurl
        res['scaninfo']['webappurl'] = '/'.join(_elements[:2])
        logger.debug('set webappurl to {}'.format(res['scaninfo']['webappurl']))
    else:
        res['scaninfo']['webappurl'] = vhost

    vulnerabilities_tag = root.find('issues')
    if not vulnerabilities_tag:
        logger.warn('no vulnerabilities tag found in scnr output')
        return res

    for issue in vulnerabilities_tag.findall('issue'):
        title = xhq_get_text(issue.find('name'))

        logger.debug('extracting data for {}'.format(title))
        severity = xhq_get_text(issue.find('severity'))

        try:
            request_tag = issue.find('page').find('request')
        except:
            logger.debug('no request tag found for {}'.format(title))
            request_tag = None

        if title in res:
            # if the current severity is higher than the stored one, use it
            if severity_map[severity] > severity_map[res[title]['severity']]:
                res[title]['severity'] = severity

            # get request url, method and any body
            if res[title]['proof']:
                res[title]['proof'] += '\n'

            res[title]['proof'] += get_proofs(request_tag)

            continue

        # runs if this is the first time this title is seen
        res[title] = { 'severity': severity }

        # get request url, method and any body
        res[title]['proof'] = get_proofs(request_tag)

        res[title]['description'] = xhq_get_text(issue.find('description'))
        res[title]['remediation'] = xhq_get_text(issue.find('remedy_guidance'))

        #NOTE there can be multiple instances of a finding e.g. XSS for a service
        # this stores only one request, with one set of parameters exploited
        res[title]['request'] = xhq_get_text(request_tag.find('raw')) if request_tag else None

    return res

def import_scan(filename, scantype, eng_id):
    status = {'error': True, 'msg': None}
    parsed_data = parse(filename, eng_id)
    if not parsed_data:
        logger.error('failed to parse scnr scan')
        return status

    logger.debug('scnr scan parsed okay, storing')
    scaninfo = parsed_data.pop('scaninfo')
    webappurl = scaninfo['webappurl']

    conn = get_db()
    curs = conn.cursor()

    curs.execute('insert into scnr_scans (engagement_id, target, filename, scan_type)\
                           values (%s, %s, %s, %s) returning id',
                           (eng_id, scaninfo['url'], filename, scantype))
    scanid = curs.fetchone()[0]
    logger.debug('scan entry stored in scnr_scans table')

    scan_uri = 'scnr/' + str(scanid)

    # check host exists in hosts table, add entry if needed
    qry = db_getrow('select id, fqdn from hosts where engagement_id = %s and (ipv4 = %s or ipv6 = %s)',
                         (eng_id, scaninfo['ipv4'], scaninfo['ipv6']))

    if qry['success']:
        host = qry['data']
    else:
        logger.error('query failed')
        status['msg'] = 'System error'
        return status

    external = True if scantype == 'external' else False
    svc_ins_sql = get_pg_insert_sql('services',
                                    ['host_id', 'protocol', 'port', 'service', 'webappurl', 'scan_uri_list', 'external'],
                                    returning='id')

    if host:
        hostid = host['id']
        svc_ins_vals = [hostid, 'tcp', scaninfo['port'], 'www', webappurl, scan_uri, external]
        logger.debug('scnr scanned host already exists, checking fqdn')
        if scaninfo['hostname']:
            if not host['fqdn']:
                logger.debug('updating fqdn for host id ' + str(hostid) + ' to ' + scaninfo['hostname'])
                curs.execute('update hosts set fqdn = %s where id = %s', (scaninfo['hostname'], hostid))

            # in all cases, try adding the virthost
            logger.debug('adding virthost for host id ' + str(hostid))
            curs.execute('insert into http_virthost (host_id, virthost) values (%s, %s) on conflict do nothing',
                            (hostid, scaninfo['hostname']))

        service = None
        if webappurl:
            # check service exists in services table, add entry if needed
            logger.debug('looking for service matching webappurl {}'.format(webappurl))
            qry = db_getrow("select id, webappurl, external, scan_uri_list from services\
                             where host_id = %s and protocol = 'tcp' and port = %s and webappurl = %s",
                                    (hostid, scaninfo['port'], webappurl))
            if qry['success']:
                service = qry['data']
            else:
                logger.error('query failed')
                status['msg'] = 'System error'
                return status

            # if webappurl is defined, and no services already matches it, create a new service entry for it
            # ignore any existing service on that host/port with null or different webappurl
            if not service:
                logger.debug('adding service entry to existing host: hostid/port - {}/{}'.format(hostid, scaninfo['port']))

                curs.execute(svc_ins_sql, tuple(svc_ins_vals))
                serviceid = curs.fetchone()[0]
                service = {'id': serviceid, 'webappurl': webappurl, 'external':external, 'scan_uri_list': scan_uri}

        else:
            logger.debug('no webappurl defined, checking for general service matches with empty webappurl')
            qry = db_getrow("select id, webappurl, external, scan_uri_list from services\
                             where host_id = %s and protocol = 'tcp' and port = %s and webappurl is null",
                                    (hostid, scaninfo['port']))

            if qry['success']:
                service = qry['data']
            else:
                logger.error('query failed')
                status['msg'] = 'System error'
                return status

        if service:
            serviceid = service['id']
            logger.debug("service id is {}".format(serviceid))
        else:
            logger.debug('adding service entry to existing host: hostid/port - {}/{}'.format(hostid, scaninfo['port']))

            curs.execute(svc_ins_sql, tuple(svc_ins_vals))
            serviceid = curs.fetchone()[0]

    else:
        logger.debug('adding new host entry for ip {}'.format(scaninfo['ipv4']))
        curs.execute('insert into hosts (engagement_id, ipv4, ipv6, fqdn) values (%s, %s, %s, %s) returning id',
                                (eng_id, scaninfo['ipv4'], scaninfo['ipv6'], scaninfo['hostname']))

        hostid = curs.fetchone()[0]
        svc_ins_vals = [hostid, 'tcp', scaninfo['port'], 'www', webappurl, scan_uri, external]

        curs.execute(svc_ins_sql, tuple(svc_ins_vals))
        serviceid = curs.fetchone()[0]

    logger.debug('host and service updated, storing issues')
    # compile scnr issues_seen
    qry = db_getdict("select id, title, severity, fingerprint from issues_seen where scanner = 'scnr'")
    if qry['success']:
        issues_seen = {x.pop('title'): x for x in qry['data']}
    else:
        logger.error('query failed')
        status['msg'] = 'System error'
        return status

    for title in parsed_data:
        logger.debug('storing finding for {}'.format(title))
        remediation = parsed_data[title]['remediation']
        description = parsed_data[title]['description']
        severity = severity_map[parsed_data[title]['severity'].strip()]
        request = parsed_data[title]['request']

        # check if the issue exists and whether scanner texts have been updated
        issue = {'title': title, 'description': description, 'remediation': remediation, 'severity': severity}
        fingerprint = get_fingerprint(issue)
        issue['fingerprint'] = fingerprint

        if title in issues_seen:
            issue_seen_id = issues_seen[title]['id']
            if fingerprint != issues_seen[title]['fingerprint']:
                logger.info('issue seen but is changed, updating: ' + title)
                cols = issue.keys()
                vals = list(issue.values())
                sql = get_pg_update_sql('issues_seen', cols, 'where id = %s')
                vals.append(issue_seen_id)

                try:
                    curs.execute(sql, tuple(vals))
                except Exception as e:
                    logger.error(e.pgerror)
                    logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to update issues_seen table')
                    status['error'] = 'Import failed'
                    return status
        else:
            logger.info('adding new issue: ' + title)
            issue['scanner'] = 'scnr'
            cols = issue.keys()
            vals = issue.values()
            placeholders = '%s,'*(len(cols) - 1) + '%s'
            sql = 'insert into issues_seen (' + ','.join(cols) + ') values (' + placeholders + ') returning id'
            curs.execute(sql, tuple(vals))
            issue_seen_id = curs.fetchone()[0]

        # issue details should now be stored, save findings
        # no uniqueness requirements in db so no need to check stored data
        logger.debug('adding finding for issue id {}/{}'.format(issue_seen_id, title))

        cols = ['engagement_id', 'service_id', 'issue_id', 'scan_uri_list', 'request', 'vhost', 'external', 'proof']
        vals = [eng_id, serviceid, issue_seen_id, scan_uri, request, webappurl, external, parsed_data[title]['proof']]
        sql = get_pg_insert_sql('findings', cols)
        try:
            curs.execute(sql, tuple(vals))
        except Exception as e:
            logger.error(e.pgerror)
            logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to insert finding entry')
            status['error'] = 'Import failed'
            return status

    conn.commit()
    curs.close()
    logger.info('scnr scan imported')

    status['error'] = False
    return status

def xhq_get_text(tag):
    '''extract text from tag, handle errors'''
    try:
        text = tag.text.strip()
        #logger.debug(text)
    except:
        logger.debug('no text in {}'.format(tag))
        text = ''

    return text

def get_proofs(request_tag):
    method = xhq_get_text(request_tag.find('method')).upper()
    proof = method + ': ' + xhq_get_text(request_tag.find('url'))

    if method == 'POST':
        body = xhq_get_text(request_tag.find('body'))
        if body:
            proof += '\nPOST BODY: {}'.format(body)

    elif method == 'GET':
        parameters_tag = request_tag.find('parameters')
        if parameters_tag:
            param_list = parameters_tag.findall('parameter')
            params = []
            for p in param_list:
                name = p.get('name')
                value = p.get('value')
                if name and value:
                    params.append('{}={}'.format(name, value))

            proof += '?' + '&'.join(params)

    return proof

# execute as standalone
def main():
    filename = sys.argv[1]
    eng_id = sys.argv[2]
    scantype = sys.argv[3]
    import_scan(filename, scantype, eng_id)

if __name__ == "__main__":
    main()
