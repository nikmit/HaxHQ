#!/usr/bin/env python3
import logging
import sys
import re
import hashlib
import warnings
import psycopg2.errors
from bs4 import BeautifulSoup
from bs4 import MarkupResemblesLocatorWarning
from inspect import currentframe, getframeinfo
from defusedxml import ElementTree
from xhq.acunetix import parse_url
from xhq.util import is_ip, get_db, db_do, db_copy, db_getcol, db_getrow, db_getdict, get_pg_update_sql, logerror, get_fingerprint

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

logger = logging.getLogger(__name__)
logger.setLevel('INFO')
logger.setLevel('DEBUG')

severity_map = {'Information': 0,
                'Low': 1,
                'Medium': 2,
                'High': 3 }

def parse(filename, eid):
    status = {'error': False}
    try:
        tree = ElementTree.parse(filename)
    except Exception as e:
        status['error'] = 'Error while parsing file: invalid XML'
        logerror(__name__, getframeinfo(currentframe()).lineno, status['error'])
        logger.error(repr(e))

        return (status, None)

    qry = db_getcol("select webappurl from services\
                     where host_id in (select id from hosts where engagement_id = %s)\
                     and webappurl like '%%/%%'", (eid,))
    webappurls = qry['data']

    logger.debug('getting any webappurls from engagement scope')
    qry = db_getcol('select target_urls from engagements where eid = %s', (eid,))
    if qry['success']:
        if qry['data']:
            for url in qry['data'][0].split(','):
                _elements = url.split('://')
                hostandpath = _elements[1] if len(_elements) > 1 else _elements[0]
                _elements = hostandpath.split('/')
                if len(_elements) > 1 and _elements[1]:
                    webappurl = '/'.join(_elements[0:2])
                    webappurls.append(webappurl)
                    logger.debug('added {} as webappurl from engagement scope'.format(webappurl))

    res = {}
    root = tree.getroot()
    parsed_urls = {}
    txt_fields = ['host', 'severity', 'confidence', 'remediationBackground', 'remediationDetail']
    for issue in root.findall('issue'):
        host_el = issue.find('host')
        ip = host_el.attrib['ip']

        hosturl = host_el.text
        if hosturl not in parsed_urls:
            logger.debug('parsing url {}'.format(hosturl))
            protocol, ip4, ip6, vhost, port = parse_url(hosturl, eid)
            logger.debug('url parsed to: ' + repr((protocol, ip4, ip6, vhost, port)))
            parsed_urls[hosturl] = [protocol, ip4, ip6, vhost, port]
        else:
            protocol, ip4, ip6, vhost, port = parsed_urls[hosturl]

        ipv = is_ip(ip)
        if not ipv and (ip4 or ip6):
            ip, ipv = (ip4, 4) if ip4 else (ip6, 6)

        res.setdefault(ip, {'ipv': ipv})

        path = issue.find('path').text
        path_elements = path.strip('/').split('/')
        # no appurl support if no domain name 
        if vhost and path_elements[0]:
            burpappurl = vhost + '/' + path_elements[0] if port in ['80', '443'] else vhost + ':' + port + '/' + path_elements[0]
        else:
            burpappurl = None

        #TODO zap way of defining zapappurl is simpler & might work here too
        if webappurls and burpappurl in webappurls:
            res[ip].setdefault(burpappurl, {})
            path = '/' + '/'.join(path_elements[1:]) if len(path_elements) > 1 else '/'
        else:
            burpappurl = vhost
            res[ip].setdefault(burpappurl, {})

        logger.debug('burpappurl: ' + str(burpappurl) + ', path: ' + str(path))

        res[ip][burpappurl].setdefault(port, {})
        res[ip][burpappurl]['vhost'] = vhost

        _name = issue.find('name').text
        logger.debug('looking at: ' + _name)

        try:
            _background = issue.find('issueBackground').text
            logger.debug('issue background found')
        except AttributeError:
            _background = None
            logger.debug('no issue background found')
            pass

        try:
            _detail = issue.find('issueDetail').text
            logger.debug('issue detail found')
        except AttributeError:
            _detail = None
            logger.debug('no issue detail found')
            pass

        if _name == '[Vulners] Vulnerable Software detected':
            logger.debug('looking for details on genericly named vulners issue')
            if _detail:
                match = re.search(r'for software <b>(.+), (?:headers|script) - ([0-9\.]+)</b>', _detail)
                if match:
                    software = match[1] + ' ' + match[2]
                    logger.debug('found software name: ' + software)
                else:
                    software = None
                    logger.debug('no software name in: ' + _detail)

            # if no detail data or no software data in detail text
            # untested
            if not software:
                if _detail:
                    hash_obj = hashlib.md5(bytes(_detail, 'utf-8'))
                    software = hash_obj.hexdigest()
                elif _background:
                    hash_obj = hashlib.md5(bytes(_background, 'utf-8'))
                    software = hash_obj.hexdigest()
                else:
                    software = 'Undetected software'

            _name = 'Vulnerable Software detected - ' + software
            logger.debug('updated name: ' + _name)
        else:
            logger.debug('no name updates needed')

        if _name in res[ip][burpappurl][port]:
            res[ip][burpappurl][port][_name]['paths'].add(path)
            logger.debug('added path ' + path + ' for previously detected issue: ' + _name)

        else:
            logger.debug('adding new issue: ' + _name)
            res[ip][burpappurl][port].setdefault(_name, {})
            res[ip][burpappurl][port][_name].setdefault('paths', set()).add(path)
            logger.debug('added path ' + path + ' for issue: ' + _name)
            res[ip][burpappurl][port][_name]['issueBackground'] = _background
            res[ip][burpappurl][port][_name]['issueDetail'] = _detail

            for fld in txt_fields:
                try:
                    res[ip][burpappurl][port][_name].setdefault(fld, issue.find(fld).text)
                except AttributeError:
                    logger.debug('field not found: ' + fld)
                    res[ip][burpappurl][port][_name].setdefault(fld, None)
                    continue
                except Exception as e:
                    status['error'] = 'Error processing burp xml'
                    logerror(__name__, getframeinfo(currentframe()).lineno, status['error'])
                    logger.error(repr(e))
                    return status, None

    return (status, res)

def import_scan(filename, scantype, eid):
    logger.debug('importing ' + str(filename))
    status, burp_issues = parse(filename, eid)
    if status['error']:
        return status

    conn = get_db()
    curs = conn.cursor()
    try:
        curs.execute('insert into burp_scans (engagement_id, filename, scan_type) values (%s, %s, %s) returning id',
                           (eid, filename, scantype))
        burp_id = curs.fetchone()[0]
    except psycopg2.errors.UniqueViolation as e:
        logger.info('Import failed (file already uploaded): ' + repr(e))
        status['error'] = 'Import failed. Is this file already imported?'
        conn.close()
        return status
    except Exception as e:
        logger.error(e.pgerror)
        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to store entry in burp_scans')
        status['error'] = 'Import failed'
        conn.close()
        return status

    scan_uri = 'burp/' + str(burp_id)

    ## compile a quick lookup dict for any existing data
    qry = db_getdict('select id, coalesce(ipv4, ipv6) as ip from hosts where engagement_id = %s', (eid,))
    existing_hosts = qry['data']
    qry = db_getdict("select id as sid, host_id, port, external, webappurl, scan_uri_list from services\
                      where protocol = 'tcp' and host_id in (select id from hosts where engagement_id = %s)", (eid,))
    existing_services = qry['data']

    hostmap = {h['ip']: str(h['id']) for h in existing_hosts}
    webappurlmap, servicemap = {}, {}
    for svc in existing_services:
        host_id = str(svc.pop('host_id'))
        port = str(svc.pop('port'))
        webappurl = svc['webappurl']
        webappurlmap[webappurl] = svc
        servicemap[host_id + '#' + port] = svc

    # compile burp issues_seen
    qry = db_getdict("select id, title, severity, fingerprint, false as updated, false as new\
                       from issues_seen where scanner = 'burp'")
    data = qry['data']
    issues_seen = {x.pop('title'): x for x in data}

    external = True if scantype == 'external' else False
    #  res[ip][burpappurl/ipv][port/vhost][_name].setdefault('paths', set()).add(path)
    for ip in burp_issues:
        ipv = burp_issues[ip].pop('ipv')
        for burpappurl in burp_issues[ip]:
            vhost = burp_issues[ip][burpappurl].pop('vhost')
            for port in burp_issues[ip][burpappurl]:
                logger.debug(ip + '/' + str(burpappurl) + '/' + port)
                for title in burp_issues[ip][burpappurl][port]:
                    # define variables to be stored
                    logger.debug('processing: ' + title)
                    issue = burp_issues[ip][burpappurl][port][title]

                    severity = severity_map[issue['severity']]
                    description = BeautifulSoup(issue['issueBackground'], 'lxml').get_text(' ')\
                            if 'issueBackground' in issue and issue['issueBackground']\
                            else ''

                    detail = ''
                    if 'issueDetail' in issue and issue['issueDetail']:
                        detail = BeautifulSoup(issue['issueDetail'], 'lxml').get_text(' ')

                    paths_str = '\n'.join(issue['paths'])
                    if detail and paths_str:
                        detail += '\n\n' + 'Affected paths:\n' + paths_str
                    else:
                        detail += paths_str

                    remediation = BeautifulSoup(issue['remediationBackground'], 'lxml').get_text(' ')\
                                  if 'remediationBackground' in issue and issue['remediationBackground']\
                                  else ''
                    if 'remediationDetail' in issue and issue['remediationDetail']:
                        remeddetail = BeautifulSoup(issue['remediationDetail'], 'lxml').get_text(' ')
                        remediation += '\n\n' + remeddetail
                        logger.debug('detail as remediation: ' + remeddetail)

                    logger.debug('issue variables set, starting work on db save')
                    # variables set, figure out storage
                    # check if host exists
                    if ip in hostmap:
                        hid = hostmap[ip]
                        logger.debug(ip + ' already exists in db')
                        if vhost:
                            logger.debug('trying to add vhost: ' + vhost)
                            curs.execute('insert into http_virthost (host_id, virthost) values (%s, %s) on conflict do nothing',
                                                (hid, vhost))

                        if burpappurl in webappurlmap:
                            svc = webappurlmap[burpappurl]
                        elif hid + '#' + port in servicemap:
                            svc = servicemap[hid + '#' + port]
                        else:
                            svc = {}

                        if svc:
                            # if existing service already matched (by webappurl or above), update exposure and scan_uri if needed
                            sid = svc['sid']
                            scan_uri_set = set(svc['scan_uri_list'].split(','))
                            scan_uri_set.add(scan_uri)
                            scan_uri_str = ','.join(scan_uri_set)

                            update_cols = ['scan_uri_list']
                            update_vals = [scan_uri_str]
                            if external and not svc['external']:
                                logger.debug('service found to be externally exposed as well, clobbering internal exposure')
                                update_cols.append('external')
                                update_vals.append(True)

                            if burpappurl and not ('webappurl' in svc and svc['webappurl']):
                                update_cols.append('webappurl')
                                update_vals.append(burpappurl)

                            update_vals.append(sid)
                            sql = get_pg_update_sql('services', update_cols, 'where id = %s')

                            curs.execute(sql, tuple(update_vals))

                        else:
                            logger.debug('adding root domain web app service at port ' + port)
                            curs.execute('insert into services (host_id, protocol, port, service, webappurl, external, scan_uri_list)\
                                                        values (%s, %s, %s, %s, %s, %s, %s) returning id',
                                                               (hid, 'tcp', port, 'www', vhost, external, scan_uri))
                            sid = curs.fetchone()[0]
                            logger.debug('updating stored data, adding ' + str(sid) + '/' + str(vhost) + '/external: ' + str(external))
                            servicemap[hid + '#' + port] = {'sid': sid, 'external': external, 'scan_uri_list': scan_uri}

                    else:
                        logger.debug('keys in hostmap: ' + repr(hostmap.keys()))
                        logger.debug('adding new host and port ' + ip + '/' + port)
                        ipcol = 'ipv' + str(ipv)
                        sql = 'insert into hosts (engagement_id, ' + ipcol + ') values (%s, %s) returning id'
                        curs.execute(sql, (eid, ip))
                        hid = str(curs.fetchone()[0])
                        hostmap[ip] = hid
                        logger.debug('added host with id ' + str(hid))

                        if vhost:
                            logger.debug('trying to add vhost: ' + vhost)
                            curs.execute('insert into http_virthost (host_id, virthost) values (%s, %s) on conflict do nothing',
                                                                    (hid, vhost))

                        curs.execute('insert into services (host_id, protocol, port, service, webappurl, external, scan_uri_list)\
                                                    values (%s, %s, %s, %s, %s, %s, %s) returning id',
                                                           (hid, 'tcp', port, 'www', vhost, external, scan_uri))
                        sid = curs.fetchone()[0]
                        logger.debug('updating stored data, adding ' + ip + '/' + str(sid) + '/external: ' + str(external))
                        servicemap[hid + '#' + port] = {'sid': sid, 'external': external, 'scan_uri_list': scan_uri}

                    # ip and service are in db, store issues
                    issue = {'title': title, 'description': description, 'remediation': remediation, 'scanner': 'burp'}
                    fingerprint = get_fingerprint(issue)
                    issue['fingerprint'] = fingerprint
                    # burp treats titles a bit like categories, e.g. 'TLS certificate' issue
                    # as a generic solution, ensure the highest severity is stored
                    # add severity after calculating fingerprint
                    issue['severity'] = severity
                    if title in issues_seen:
                        issue_seen_id = issues_seen[title]['id']
                        if fingerprint == issues_seen[title]['fingerprint']:
                            if int(severity) > int(issues_seen[title]['severity']):
                                logger.warn('issue seen at higher severity, updating: ' + title)
                                curs.execute('update issues_seen set severity = %s where id = %s', (severity, issue_seen_id))
                        else:
                            if issues_seen[title]['new'] or issues_seen[title]['updated']:
                                # if figerprint changes within a single file import,there's an issue there
                                logerror(__name__, getframeinfo(currentframe()).lineno, 'issue fingerprint flapping')
                                logger.error('fingerprint flapping at title ' + title)
                            else:
                                logger.info('issue seen but is changed, updating: ' + title)

                            cols = issue.keys()
                            vals = list(issue.values())
                            sql = get_pg_update_sql('issues_seen', cols, 'where id = %s')
                            vals.append(issue_seen_id)

                            try:
                                curs.execute(sql, tuple(vals))
                            except Exception as e:
                                logger.error(e.pgerror)
                                logerror(__name__, getframeinfo(currentframe()).lineno, 'query failed')
                                status['error'] = 'Import failed'
                                conn.close()
                                return status

                            # this should only be needed if we ever start processing exports containing multiple scans
                            issues_seen[title]['fingerprint'] = fingerprint
                            issues_seen[title]['updated'] = True
                    else:
                        logger.info('adding new issue: ' + title)
                        issue['scanner'] = 'burp'
                        cols = issue.keys()
                        vals = issue.values()
                        placeholders = '%s,'*(len(cols) - 1) + '%s'
                        sql = 'insert into issues_seen (' + ','.join(cols) + ') values (' + placeholders + ') returning id'
                        curs.execute(sql, tuple(vals))
                        issue_seen_id = curs.fetchone()[0]
                        # this should only be needed if we ever start processing exports containing multiple scans
                        issues_seen[title] = {'id': issue_seen_id, 'fingerprint': fingerprint, 'severity': severity, 'new': True}

                    # issue details should now be stored, save findings
                    logger.debug('storing texts for issue ' + title)
                    curs.execute('insert into findings (engagement_id, service_id, issue_id, scan_uri_list, vhost, external,\
                                                        proof)\
                                                values (%s, %s, %s, %s, %s, %s, %s)',
                                 (eid, sid, issue_seen_id, scan_uri, burpappurl, external, detail))

    conn.commit()
    conn.close()
    logger.debug('burp import comleted')
    return status
