import re
import sys
import logging
import psycopg2.errors
import warnings
from bs4 import BeautifulSoup
from bs4 import MarkupResemblesLocatorWarning
from markupsafe import escape
from inspect import currentframe, getframeinfo
from defusedxml import ElementTree
from xhq.util import is_ip, get_db, db_do, db_copy, db_getcol, db_getrow, db_getdict, resolve, get_pg_update_sql, multiple_replace, logerror, get_fingerprint

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

logger = logging.getLogger(__name__)
logger.setLevel('INFO')
logger.setLevel('DEBUG')

severity_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'informational': 0}

def resolve_no_dns(eng_id, hostname):
    logger.debug('name lookup failed, looking for matching hosts in engagement ' + str(eng_id))
    # check database to see if fqdn or vhost exists, could be an internal scan
    qry = db_getrow('select ipv4, ipv6 from hosts where engagement_id = %s\
                            and (fqdn = %s or id = (select host_id from http_virthost where virthost = %s limit 1))',
                            (eng_id, hostname, hostname))
    stored = qry['data']
    if stored:
        ip4 = stored['ipv4']
        ip6 = stored['ipv6']
    else:
        # add fake IPs
        # check if any IPs auto generated
        qry = db_getcol("select max(ipv4) from hosts where engagement_id = %s and ipv4::text like '0.0.0.%%'", (eng_id,))
        max_fake_ip = qry['data']
        if max_fake_ip and max_fake_ip[0]:
            # if yes, pick up the greatest number in the last octet
            n = int(max_fake_ip[0].split('.')[-1])
            logger.debug('seen ' + str(n) + ' fake IPs')
        else:
            n = 0

        ip4 = '0.0.0.' + str(n + 1)
        ip6 = None

    return (ip4, ip6)

def parse_url(scanned_url, eng_id):
    'parse a url and return protocol, ipv4, ipv6, hostname and port as strings'
    hostname = None
    ip4 = None
    ip6 = None
    port = None

    proto, url = scanned_url.split('://')
    if re.search('/', url):
        parts = url.split('/')
        hostport = parts[0]
    else:
        hostport = url.strip()

    # handle https://[2001:1234::1]:8443 and https://[2001:1234::1]
    m = re.match('^\[([\d:]+)\](?::(\d+))?$', hostport)
    if m:
        ip6 = m.group(1)
        port = m.group(2)
        hostname = None

    else:
        # if no ipv6 address in url, check for custom port
        if re.search(':', hostport):
            hostname, port = hostport.split(':')
        else:
            hostname = hostport

        ipv = is_ip(hostname)
        if ipv:
            if ipv == 4:
                ip4 = hostname
            else:
                ip6 = hostname

            hostname = None
        else:
            # at this point whatever is in hostname shouldn't be an IP in any form
            # see what it resolves to
            logger.debug('attempting to resolve hostname ' + hostname)
            _res = resolve(hostname)
            ip4 = _res['ipv4']
            ip6 = _res['ipv6']

            if not ip4 and not ip6:
                ip4, ip6 = resolve_no_dns(eng_id, hostname)

    if not port:
        # if no custom port was picked up, assign defaults
        port = '443' if proto == 'https' else '80'

    return proto, ip4, ip6, hostname, port


def parse(filename, eng_id):
    status = {'error': False, 'msg': None}
    replacemap = {'\x1B': 'ESC', '\x00': 'NULL'}
    with open(filename, 'r') as f:
        content = f.read()
        sanitised = multiple_replace(replacemap, content)
        if content != sanitised:
            status['msg'] = 'filtered NULL and/or ESC sequences from ' + filename
            with open(filename + '_sanitised', 'w') as f2:
                f2.write(sanitised)

            filename += '_sanitised'

    try:
        tree = ElementTree.parse(filename)
    except ElementTree.ParseError as e:
        status['error'] = 'Invalid XML: ' + repr(e)
        logerror(__name__, getframeinfo(currentframe()).lineno, status['error'])
        return status, None
    except Exception as e:
        status['error'] = repr(e)
        logerror(__name__, getframeinfo(currentframe()).lineno, status['error'])
        return status, None

    root = tree.getroot()

    # get basic info about the target
    proto = None
    crawler = root.find('Scan').find('Crawler')
    if crawler:
        # scanned_url is whatever was entered as the target, it may be just the hostname or contain http:// prefix
        scanned_url = crawler.get('StartUrl')

        sitefiles = crawler.find('SiteFiles').findall('SiteFile')
        for sitefile in sitefiles:
            try:
                full_url = sitefile.find('FullURL').text.strip()
                break
            except:
                continue

        logger.debug('scanned URL: ' + scanned_url)
        proto, ip4, ip6, hostname, port = parse_url(full_url, eng_id)

    else:
        # some files don't contain a Crawler tag :/
        # get hostname from details in issue and any path from file name
        logger.info('no Crawler tag, attemting to get hostname from Host: header in requests')
        reportitems = root.find('Scan').find('ReportItems').findall('ReportItem')
        # this only checks the first issue that has a request stored
        request = None
        i = 0
        while not request and i < len(list(reportitems)):
            req_el = reportitems[i].find('TechnicalDetails').find('Request')
            request = req_el.text
            i += 1

        port = None
        elements = request.split('\n')
        for el in elements:
            if el.startswith('Host: '):
                hoststr = el[6:]
                # check for non-standard port
                if re.search(':', hoststr):
                    hostname, port = hoststr.split(':')
                else:
                    hostname = hoststr

        if hostname:
            # check the extracted hostname against the filename, to extract protocol and any path info
            logger.info('got hostname ' + hostname + ', checking xml file name')
        else:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to get hostname from Host headers in report requests')
            status['error'] = 'Could not determine scanned hostname: Crawler tag missing in XML, fallback to Host headers in report requests failed.'
            return status, None

        m = re.match('.*_XML_(https?)_', filename)
        if m:
            proto = m[1]
        else:
            # acunetix xml filenames seem to omit the protocol if it is http
            proto = 'http'

        # construct the expected filename and see if there is any path in it
        filename_exp = '_XML_'
        filename_exp += 'https_' if proto == 'https' else ''
        filename_exp += hostname.replace('.', '_')
        if port:
            # if port is already defined it will be non-standard and therefore part of the url and filename
            filename_exp += '_' + str(port)
            scanned_url = proto + '://' + hostname + ':' + str(port) + '/'
        else:
            port = 80 if proto == 'http' else 443
            scanned_url = proto + '://' + hostname + '/'

        m = re.match('.*' + filename_exp + '(.*)?_?\.xml', filename)
        if m:
            folders = m[1].split('_')
            for path in folders:
                if path:
                    scanned_url += path + '/'

            logger.debug('scanned url: ' + scanned_url)
        else:
            m = re.match('.*' + filename_exp + '_?\.xml', filename)
            if m:
                logger.debug('scanned url: ' + scanned_url)
            else:
                logger.debug('failed to confirm extracted hostname with file name: ' + filename_exp + '|' + filename)
                status['error'] = 'Could not conclusively determine scanned hostname: Crawler tag missing in XML.'
                return status, None

        ipv = is_ip(hostname)
        if ipv:
            if ipv == 4:
                ip4 = hostname
                ip6 = None
            # this will hardly ever match and may be buggy, not sure how acunetix will use v6 addresses
            elif ipv == 6:
                ip4 = None
                ip6 = hostname
        else:
            resolved = resolve(hostname)
            ip4 = resolved['ipv4']
            ip6 = resolved['ipv6']

            if not ip4 and not ip6:
                ip4, ip6 = resolve_no_dns(eng_id, hostname)

    res = {'scaninfo': {'ipv4': ip4, 'ipv6': ip6, 'hostname': hostname, 'proto': proto, 'port': port, 'url': scanned_url}}

    hostandpath = scanned_url.split('://')[1] if scanned_url.startswith('http') else scanned_url
    _elements = hostandpath.split('/')
    if len(_elements) > 2:
        # we have host.tld/path/path_or_cgi etc, set host.tld/path as webappurl
        res['scaninfo']['webappurl'] = '/'.join(_elements[:2])
        logger.debug('set webappurl to {}'.format(res['scaninfo']['webappurl']))
    else:
        res['scaninfo']['webappurl'] = hostname


    for issue in root.find('Scan').find('ReportItems').findall('ReportItem'):
        title = issue.find('Name').text.strip()
        res.setdefault(title, {})
        logger.debug('checking ' + title)

        try:
            request = issue.find('TechnicalDetails').find('Request').text
        except:
            request = None
            logger.debug('no request found in tecnical details for ' + title)
        else:
            res[title].setdefault('request', []).append(request)

        for x in ['cvss3', 'cvss']:
            cvss_tag = issue.find(x.upper())
            if cvss_tag:
                logger.debug(title + ': ' + x + ' tag found')
                _value = cvss_tag.find('Score').text.strip()
                logger.debug(title + ': ' + x + ' score - ' + _value)
                res[title][x] = _value
                _vector = cvss_tag.find('Descriptor').text.strip()
                logger.debug(title + ': ' + x + ' vector - ' + _vector)
                res[title][x + '_vector'] = _vector

        references = []
        for ref in issue.find('References').findall('Reference'):
            link = ref.find('URL').text.strip()
            references.append(link)

        res[title].setdefault('references', '\n'.join(references))


        for tag in ['Severity', 'Description', 'Impact', 'Recommendation']:
            try:
                _tag = issue.find(tag).text.strip()
                if tag != 'Severity':
                    for el in ['<br/>', '<code>', '</code>']:
                        _tag = _tag.replace(el, '\n', 1)

                data = BeautifulSoup(_tag, 'lxml').get_text(' ')
            except AttributeError:
                logger.debug('tag not found: ' + tag)
            except Exception as e:
                logerror(__name__, getframeinfo(currentframe()).lineno, e)
            else:
                if data:
                    res[title].setdefault(tag.lower(), data)

            if tag not in res[title]:
                res[title].setdefault(tag, None)

        logger.debug('looking for details section in ' + title)
        try:
            details = issue.find('Details').text
        except:
            logger.debug('no details section in ' + title)
        else:
            logger.debug('details found')
            for el in ['<br/>', '<code>', '</code>']:
                _tag = _tag.replace(el, '\n', 1)

            details = BeautifulSoup(details, 'lxml').get_text(' ')
            res[title].setdefault('plugin_output', []).append(details)
            logger.debug(res[title]['plugin_output'])

    if 'plugin_output' in res[title]:
        res[title]['plugin_output'] = '####'.join(res[title]['plugin_output'])
        logger.debug(res[title]['plugin_output'])

    if 'request' in res[title]:
        res[title]['request'] = '####'.join(res[title]['request'])
        #TODO remove this
        res[title]['plugin_output'] += '\n\nRequest:' + res[title]['request']

    return (status, res)

def import_scan(filename, scantype, eng_id):
    status, parsed_data = parse(filename, eng_id)
    if status['error']:
        return status

    scaninfo = parsed_data.pop('scaninfo')

    conn = get_db()
    curs = conn.cursor()

    try:
        curs.execute('insert into acunetix_scans (engagement_id, target, filename, scan_type)\
                               values (%s, %s, %s, %s) returning id',
                               (eng_id, scaninfo['url'], filename, scantype))
        scanid = curs.fetchone()[0]
    except psycopg2.errors.UniqueViolation as e:
        logger.warn('Import failed: ' + repr(e))
        status['error'] = 'Import failed. Is this file already imported?'
        return status
    except Exception as e:
        logger.error(e.pgerror)
        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to store entry in acunetix_scans')
        status['error'] = 'Import failed'
        return status

    scan_uri = 'acunetix/' + str(scanid)
    webappurl = scaninfo['webappurl']

    # check host exists in hosts table, add entry if needed
    qry = db_getrow('select id from hosts where engagement_id = %s and (ipv4 = %s or ipv6 = %s)',
                         (eng_id, scaninfo['ipv4'], scaninfo['ipv6']))
    host = qry['data']
    if host:
        hostid = host['id']
        logger.debug('host already exists: {}'.format(hostid))
        if scaninfo['hostname']:
            logger.debug('adding virthost for host id {}'.format(hostid))
            curs.execute('insert into http_virthost (host_id, virthost) values (%s, %s) on conflict do nothing',
                            (hostid, scaninfo['hostname']))

        service = None
        if webappurl:
            # check service exists in services table, add entry if needed
            logger.debug('looking for service matching webappurl ' + str(webappurl))
            qry = db_getrow("select id, webappurl, external, scan_uri_list from services\
                             where host_id = %s and protocol = 'tcp' and port = %s and webappurl = %s",
                                    (hostid, scaninfo['port'], webappurl))
            service = qry['data']

        if not service:
            logger.debug('no service matched webappurl ' + str(webappurl) + ', checking for matches from general scanners')
            qry = db_getrow("select id, webappurl, external, scan_uri_list from services\
                             where host_id = %s and protocol = 'tcp' and port = %s and webappurl is null",
                                    (hostid, scaninfo['port']))
            service = qry['data']

        if service:
            serviceid = service['id']
            logger.debug("service found: " + str(serviceid))

            scan_uri_set = set(service['scan_uri_list'].split(','))
            scan_uri_set.add(scan_uri)
            scan_uri_list = ','.join(scan_uri_set)

            exposure = 'external' if service['external'] else 'internal'
            logger.debug('current exposure: '  + exposure + ', scan_uri_list: ' + scan_uri_list)

            update_cols = ['scan_uri_list']
            update_vals = [scan_uri_list]
            if exposure == 'internal' and scantype == 'external':
                logger.debug('service found to be externally exposed as well, clobbering internal exposure')
                update_cols.append('external')
                update_vals.append(True)

            if webappurl and not service['webappurl']:
                update_cols.append('webappurl')
                update_vals.append(webappurl)

            update_vals.append(serviceid)
            sql = get_pg_update_sql('services', update_cols, 'where id = %s')

            curs.execute(sql, tuple(update_vals))
        else:
            logger.debug('adding service entry to existing host: hostid/port - ' + str(hostid) + '/' + str(scaninfo['port']))
            sql = 'insert into services (host_id, protocol, port, service, webappurl, scan_uri_list'
            if scantype == 'external':
                sql += ", external) values (%s, 'tcp', %s, 'www', %s, %s, true) returning id"
            else:
                # default exposure is internal (external = false)
                sql += ") values (%s, 'tcp', %s, 'www', %s, %s) returning id"

            curs.execute(sql, (hostid, scaninfo['port'], webappurl, scan_uri))
            serviceid = curs.fetchone()[0]
    else:
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

    # compile acunetix issues_seen
    qry = db_getdict("select id, title, severity, fingerprint from issues_seen where scanner = 'acunetix'")
    data = qry['data'] if qry['data'] else []
    issues_seen = {x.pop('title'): x for x in data}

    for title in parsed_data:
        # recommendation tag was missing in some cases
        solution = parsed_data[title]['recommendation'] if 'recommendation' in parsed_data[title] else ''

        ext_ref = parsed_data[title]['references']
        if ext_ref:
            solution += '\n\n' + ext_ref

        sevword = parsed_data[title]['severity'].lower()
        severity = str(severity_map[sevword])

        description = parsed_data[title]['description']

        impact = parsed_data[title]['impact'] if 'impact' in parsed_data[title] else None
        plugin_output = parsed_data[title]['plugin_output']
        request = parsed_data[title]['request'] if 'request' in parsed_data[title] else None
        cvss3 = parsed_data[title]['cvss3'] if 'cvss3' in parsed_data[title] else None
        cvss3_vector = parsed_data[title]['cvss3_vector'] if 'cvss3_vector' in parsed_data[title] else None
        cvss = parsed_data[title]['cvss'] if 'cvss' in parsed_data[title] else None
        cvss_vector = parsed_data[title]['cvss_vector'] if 'cvss_vector' in parsed_data[title] else None

        # check if the issue exists and whether scanner texts have been updated
        # request is ignored here, used later
        issue = {'title': title, 'description': description, 'remediation': solution, 'impact': impact,
                 'severity': severity, 'cvss3': cvss3, 'cvss3_vector': cvss3_vector, 'cvss': cvss, 'cvss_vector': cvss_vector}
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

                # this should only be needed if we ever start processing exports containing multiple scans
                issues_seen[title]['fingerprint'] = fingerprint
        else:
            logger.info('adding new issue: ' + title)
            issue['scanner'] = 'acunetix'
            cols = issue.keys()
            vals = issue.values()
            placeholders = '%s,'*(len(cols) - 1) + '%s'
            sql = 'insert into issues_seen (' + ','.join(cols) + ') values (' + placeholders + ') returning id'
            curs.execute(sql, tuple(vals))
            issue_seen_id = curs.fetchone()[0]
            # this should only be needed if we ever start processing exports containing multiple scans
            issues_seen[title] = {'id': issue_seen_id, 'fingerprint': fingerprint, 'severity': severity}

        # issue details should now be stored, save findings
        # no uniqueness requirements in db so no need to check stored data
        external = True if scantype == 'external' else False
        logger.debug('adding finding for issue id ' + str(issue_seen_id) + '/' + title)
        try:
            curs.execute('insert into findings (engagement_id, service_id, issue_id, scan_uri_list,\
                                                plugin_output, request, vhost, external)\
                                      values (%s, %s, %s, %s, %s, %s, %s, %s)',
                                      (eng_id, serviceid, issue_seen_id, scan_uri, plugin_output, request, webappurl, external))
        except Exception as e:
            logger.error(e.pgerror)
            logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to insert finding entry')
            status['error'] = 'Import failed'
            return status

    conn.commit()
    conn.close()

    logger.info('acunetix scan imported')
    return status

# execute as standalone
def main():
    filename = sys.argv[1]
    eng_id = sys.argv[2]
    scantype = sys.argv[3]
    #res = parse(filename, eng_id)
    #print(repr(res))
    import_scan(filename, scantype, eng_id)

if __name__ == "__main__":
    main()
