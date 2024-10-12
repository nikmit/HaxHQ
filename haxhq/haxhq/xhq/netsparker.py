import re
import sys
import logging
import warnings
from bs4 import BeautifulSoup, SoupStrainer
from bs4 import MarkupResemblesLocatorWarning
from inspect import currentframe, getframeinfo
from defusedxml import ElementTree
from xhq.acunetix import parse_url
from xhq.util import is_ip, get_db, db_do, db_getcol, db_getrow, db_getdict, resolve, logerror, get_fingerprint, get_pg_update_sql, get_pg_insert_sql

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

logger = logging.getLogger(__name__)
logger.setLevel('DEBUG')

severity_map = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Information': 0, 'BestPractice': 0}

def parse(filename, eng_id):
    try:
        tree = ElementTree.parse(filename)
    except Exception as e:
        logger.error("Error: {}".format(e))
        return False

    root = tree.getroot()

    # get basic info about the target
    target_tag = root.find('target')
    if not target_tag:
        logger.error('No target tag found in netsparker xml')
        return False

    scanned_url = xhq_get_text(target_tag.find('url'))

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

    vulnerabilities_tag = root.find('vulnerabilities')
    if not vulnerabilities_tag:
        logger.warn('no vulnerabilities tag found in netsparker output')
        return res

    for issue in vulnerabilities_tag.findall('vulnerability'):
        title = xhq_get_text(issue.find('name'))
        state = xhq_get_text(issue.find('state'))
        if state != 'Present':
            logger.debug('Ignoring finding {} with state {}'.format(title, state))
            continue

        logger.debug('extracting data for {}'.format(title))
        severity = xhq_get_text(issue.find('severity'))

        request_tag = issue.find('http-request')
        if title in res:
            # if the current severity is higher than the stored one, use it
            if severity_map[severity] > severity_map[res[title]['severity']]:
                res[title]['severity'] = severity

            # get request url, method and any body
            res[title]['proof'] += '\n' + get_proofs(issue, request_tag)
            # get any proof of exploitation from description html
            throwaway, proof_list = process_description(issue)
            if proof_list:
                res[title]['proof'] += '\nProof of exploit:\n'
                for proof in proof_list:
                    res[title]['proof'] += proof

            continue

        # runs if this is the first time this title is seen
        res[title] = { 'severity': severity }

        # get request url, method and any body
        res[title]['proof'] = get_proofs(issue, request_tag)
        # get generic description and any proof of exploitation from description html
        res[title]['description'], proof_list = process_description(issue)
        if proof_list:
            res[title]['proof'] += '\nProof of exploit:\n'
            for proof in proof_list:
                res[title]['proof'] += proof
        else:
            logger.debug('no proof details for {}'.format(title))

        for tag in ['impact', 'remedial-procedure', 'remedial-actions', 'exploitation-skills',
                    'external-references', 'remedy-references', 'proof-of-concept']:

            html = xhq_get_text(issue.find(tag))
            if html:
                res[title][tag] = BeautifulSoup(html, 'lxml').get_text(' ')

            if tag not in res[title]:
                res[title][tag] = None

        for tag in ['external-references', 'remedy-references']:
            html = xhq_get_text(issue.find(tag))
            if html:
                res[title][tag] = []
                for link in BeautifulSoup(html, 'lxml', parse_only=SoupStrainer('a')):
                    if link.has_attr('href'):
                        res[title][tag].append(link['href'])

        res[title]['cvss3_vector'] = None
        res[title]['cvss3'] = None
        classification_tag = issue.find('classification')
        cvss_tag = classification_tag.find('cvss31') if classification_tag else None

        if cvss_tag:
            logger.debug('got cvss3 tag')
            res[title]['cvss3_vector'] = xhq_get_text(cvss_tag.find('vector'))
            logger.debug('found cvss3 vector: {}'.format(res[title]['cvss3_vector']))

            cvss_scores_list = cvss_tag.findall('score')
            for score_tag in cvss_scores_list:
                _type = xhq_get_text(score_tag.find('type'))
                if _type == 'Base':
                    res[title]['cvss3'] = xhq_get_text(score_tag.find('value'))
                    logger.debug('found cvss3 score: {}'.format(res[title]['cvss3']))

        request_tag = issue.find('http-request')
        res[title]['request'] = xhq_get_text(request_tag.find('content')) if request_tag else None

        notes = ''
        xtrainfo = issue.find('extra-information')
        if xtrainfo:
            for info in xtrainfo.findall('info'):
                info_name = BeautifulSoup(info.get('name'), 'lxml').get_text(' ')
                info_value = BeautifulSoup(info.get('value'), 'lxml').get_text(' ')
                if info_name and info_value:
                    if info_name == 'Notes':
                        notes += info_value
                    else:
                        notes += info_name + ': ' + info_value + '\n'

        knownvulns = issue.find('known-vulnerabilities')
        if knownvulns:
            notes += '\nKnown vulnerabilities:\n'
            for vuln in knownvulns.findall('known-vulnerability'):
                for tag in ['title', 'severity', 'references', 'affectedversions']:
                    text = xhq_get_text(vuln.find(tag))
                    if text:
                        notes += '{}: {}\n'.format(tag, text)

        res[title]['plugin_output'] = notes

    return res

def import_scan(filename, scantype, eng_id):
    status = {'error': True, 'msg': None}
    parsed_data = parse(filename, eng_id)
    if not parsed_data:
        logger.error('failed to parse netsparker scan')
        return status

    logger.debug('netsparker scan parsed okay, storing')
    scaninfo = parsed_data.pop('scaninfo')

    conn = get_db()
    curs = conn.cursor()

    curs.execute('insert into netsparker_scans (engagement_id, target, filename, scan_type)\
                           values (%s, %s, %s, %s) returning id',
                           (eng_id, scaninfo['url'], filename, scantype))
    scanid = curs.fetchone()[0]
    logger.debug('scan entry stored in netsparker_scans table')

    scan_uri = 'netsparker/' + str(scanid)
    webappurl = scaninfo['webappurl']

    # check host exists in hosts table, add entry if needed
    qry = db_getrow('select id, fqdn from hosts where engagement_id = %s and (ipv4 = %s or ipv6 = %s)',
                         (eng_id, scaninfo['ipv4'], scaninfo['ipv6']))

    if qry['success']:
        host = qry['data']
    else:
        logger.error('query failed')
        status['msg'] = 'System error'
        return status

    if host:
        hostid = host['id']
        logger.debug('netsparker scanned host already exists, checking fqdn')
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

        if not service:
            logger.debug('no service matched webappurl {}, checking for matches from general scanners'.format(webappurl))
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
            logger.debug("service found: {}".format(serviceid))
        else:
            logger.debug('adding service entry to existing host: hostid/port - {}/{}'.format(hostid, scaninfo['port']))

            sql = 'insert into services (host_id, protocol, port, service, webappurl, scan_uri_list'
            if scantype == 'external':
                sql += ", external) values (%s, 'tcp', %s, 'www', %s, %s, true) returning id"
            else:
                # default exposure is internal (external = false)
                sql += ") values (%s, 'tcp', %s, 'www', %s, %s) returning id"

            curs.execute(sql, (hostid, scaninfo['port'], webappurl, scan_uri))
            serviceid = curs.fetchone()[0]

    else:
        logger.debug('adding new host entry for ip {}'.format(scaninfo['ipv4']))
        curs.execute('insert into hosts (engagement_id, ipv4, ipv6, fqdn) values (%s, %s, %s, %s) returning id',
                                (eng_id, scaninfo['ipv4'], scaninfo['ipv6'], scaninfo['hostname']))
        hostid = curs.fetchone()[0]
        sql = 'insert into services (host_id, protocol, port, service, webappurl, scan_uri_list'
        if scantype == 'external':
            sql += ", external) values (%s, 'tcp', %s, 'www', %s, %s, true) returning id"
        else:
            # default exposure is internal (external = false)
            sql += ") values (%s, 'tcp', %s, 'www', %s, %s) returning id"
        curs.execute(sql, (hostid, scaninfo['port'], webappurl, scan_uri))
        serviceid = curs.fetchone()[0]

    logger.debug('host and service updated, storing issues')
    # compile netsparker issues_seen
    qry = db_getdict("select id, title, severity, fingerprint from issues_seen where scanner = 'netsparker'")
    if qry['success']:
        issues_seen = {x.pop('title'): x for x in qry['data']}
    else:
        logger.error('query failed')
        status['msg'] = 'System error'
        return status

    for title in parsed_data:
        logger.debug('storing finding for {}'.format(title))
        solution = parsed_data[title]['remedial-procedure'] if parsed_data[title]['remedial-procedure'] else ''
        actions = parsed_data[title]['remedial-actions']
        if actions:
            actions = re.sub('See the remedy for solution.', '', actions.strip())
            actions = re.sub('\n ', '\n', actions)
            solution += '\n\nActions to take:\n' + re.sub('See the remedy for solution.', '', actions.strip())

        description = re.sub('\n ', '\n', parsed_data[title]['description'])
        if parsed_data[title]['proof-of-concept']:
            description += '\n\n' + parsed_data[title]['proof-of-concept']

        ext_ref = parsed_data[title]['external-references']
        if ext_ref:
            description += '\n\n' + '\n'.join(ext_ref)

        rem_ref = parsed_data[title]['remedy-references']
        if rem_ref:
            solution += '\n\n' + '\n'.join(rem_ref)

        severity = severity_map[parsed_data[title]['severity'].strip()]

        exploitability = parsed_data[title]['exploitation-skills']

        impact = parsed_data[title]['impact']
        plugin_output = parsed_data[title]['plugin_output']

        cvss3 = parsed_data[title]['cvss3']
        cvss3_vector = parsed_data[title]['cvss3_vector']
        request = parsed_data[title]['request']

        # check if the issue exists and whether scanner texts have been updated
        issue = {'title': title, 'description': description, 'remediation': solution, 'impact': impact,
                 'exploitability_ease': exploitability, 'severity': severity, 'cvss3': cvss3, 'cvss3_vector': cvss3_vector}
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
            issue['scanner'] = 'netsparker'
            cols = issue.keys()
            vals = issue.values()
            placeholders = '%s,'*(len(cols) - 1) + '%s'
            sql = 'insert into issues_seen (' + ','.join(cols) + ') values (' + placeholders + ') returning id'
            curs.execute(sql, tuple(vals))
            issue_seen_id = curs.fetchone()[0]

        # issue details should now be stored, save findings
        # no uniqueness requirements in db so no need to check stored data
        external = True if scantype == 'external' else False

        logger.debug('adding finding for issue id {}/{}'.format(issue_seen_id, title))

        cols = ['engagement_id', 'service_id', 'issue_id', 'scan_uri_list', 'plugin_output', 'request', 'vhost', 'external', 'proof']
        vals = [eng_id, serviceid, issue_seen_id, scan_uri, plugin_output, request, webappurl, external, parsed_data[title]['proof']]
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
    logger.info('netsparker scan imported')

    status['error'] = False
    return status

def xhq_get_text(tag):
    '''extract text from tag, handle errors'''
    try:
        text = tag.text.strip()
        #logger.debug(text)
    except:
        logger.debug('tag {} not found or empty'.format(tag))
        text = ''

    return text

def get_proofs(issue, request_tag):
    proof = ''
    method = request_tag.find('method').text
    if method == 'POST':
        proof = method + ': ' + xhq_get_text(issue.find('url'))
        params_tag = request_tag.find('parameters')
        if params_tag:
            paramlist = []
            params = params_tag.findall('parameter')
            for p in params:
                _type = p.get('type')
                logger.debug('###' + _type)
                if _type != 'Querystring':
                    if _type == 'Json':
                        paramlist.append('{' + '{}={}'.format(p.get('name'), p.get('value')) + '}')
                    else:
                        paramlist.append('{}={}'.format(p.get('name'), p.get('value')))

            if paramlist:
                proof += '\nPOST BODY: {}'.format('&'.join(paramlist))

    else:
        proof = method + ': ' + xhq_get_text(issue.find('url'))

    return proof

def process_description(issue):
    '''extract text from html. process any proof in description and return it separately'''
    description_items, proof_items = [], []
    in_proof_section = False

    html = xhq_get_text(issue.find('description'))
    if html:
        soup = BeautifulSoup(html, 'lxml')
        item, value = None, None
        for el in soup.findChildren():
            if not in_proof_section:
                if el.name == 'p':
                    description_items.append(el.get_text())
                elif el.name == 'h2' and el.get_text() == 'Proof of Exploit':
                    logger.debug('detailed proof section in description')
                    in_proof_section = True
            else:
                if el.name == 'h4' and not item and not value:
                    item = el.get_text()
                    logger.debug('proof item: {}'.format(item))
                elif el.name == 'pre' and item:
                    value = el.get_text()
                    logger.debug('proof value: {}'.format(value))
                    proof_items.append({'item': item, 'value': value})
                    item, value = None, None
                else:
                    logger.debug('ignoring {}; item is {}'.format(el.name, item))

    logger.debug('got {} proof items'.format(len(proof_items)))
    description = ' '.join(description_items)
    proof_list = [ '{}: {}\n'.format(i['item'], i['value']) for i in proof_items ]

    return description, proof_list
# execute as standalone
def main():
    filename = sys.argv[1]
    eng_id = sys.argv[2]
    scantype = sys.argv[3]
    import_scan(filename, scantype, eng_id)

if __name__ == "__main__":
    main()
