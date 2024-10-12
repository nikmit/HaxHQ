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
from xhq.netsparker import xhq_get_text
from xhq.util import is_ip, get_db, db_do, db_copy, db_getcol, db_getrow, db_getdict, get_pg_update_sql, get_pg_insert_sql, logerror, get_fingerprint

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

    logger.debug('xml parsed, getting any stored webappurls')
    # get any stored webappurls which contain a path
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

    hosts = {}
    for site in root.findall('site'):
        baseurl = site.get('name')
        logger.debug('scan target: {}'.format(baseurl))
        hostname = site.get('host')
        port = site.get('port')
        protocol = 'https' if site.get('ssl') == 'true' else 'http'
        if hostname in hosts:
            hosts[hostname][port] = {'protocol': protocol, 'baseurl': baseurl}
        else:
            hosts[hostname] = { port: {'protocol': protocol, 'baseurl': baseurl}}

        parsed_urls = {}

        alerts_tag = site.find('alerts')
        if not alerts_tag:
            logger.warn('Empty ZAP report, nothing to parse')
            return status, {}
        else:
            issue_list = alerts_tag.findall('alertitem')
            logger.debug('found {} issues in xml'.format(len(issue_list)))

        for issue in issue_list:
            #host_el = issue.find('host')
            #ip = host_el.attrib['ip']

            # compile issue details
            title = xhq_get_text(issue.find('name'))
            logger.debug('checking {}'.format(title))

            finding = {}
            finding['severity'] = xhq_get_text(issue.find('riskcode'))
            content = xhq_get_text(issue.find('desc'))
            finding['description'] = BeautifulSoup(content, 'lxml').get_text(' ')
            content = xhq_get_text(issue.find('solution'))
            finding['remediation'] = BeautifulSoup(content, 'lxml').get_text(' ')
            desc_ref = xhq_get_text(issue.find('reference'))
            if desc_ref:
                finding['description'] += '\n' + desc_ref

            finding['details'] = xhq_get_text(issue.find('otherinfo'))
            if finding['details']:
                logger.debug('added finding details')

            evidence = xhq_get_text(issue.find('evidence'))
            if evidence:
                finding['details'] += '\n' + BeautifulSoup(evidence, 'lxml').get_text(' ')
                logger.debug('added evidence to finding details')

            instances = issue.find('instances').findall('instance')
            logger.debug('finding detected in {} instances'.format(len(instances)))

            for inst in instances:
                request_url = xhq_get_text(inst.find('uri'))
                request_method = xhq_get_text(inst.find('method'))
                request_body = xhq_get_text(inst.find('requestbody'))
                request = xhq_get_text(inst.find('requestheader'))
                if request_body:
                    request += '\n' + request_body

            proto, hostandpath = request_url.split('://')
            _elements = hostandpath.strip('/').split('/')
            if len(_elements) > 2:
                # webappurl can be definitively set only when scanners include path in target scpecification
                # burp and zap don't - when scanning http://host.tld/app target is http://host.tld
                # provisionally define zapappurl and try to match it to webappurl from other scans to provide support
                # we have host.tld/path/path_or_cgi etc, set host.tld/path as zapappurl
                zapappurl = '/'.join(_elements[:2])
                logger.debug('set zapappurl to {}'.format(zapappurl))
                hosturl = proto + '://' + zapappurl
            else:
                zapappurl = None
                hosturl = proto + '://' + _elements[0]

            # get ip for host (fake if needed)
            # avoid repeatedly parsing urls for efficiency
            if hosturl not in parsed_urls:
                logger.debug('parsing url {}'.format(hosturl))
                protocol, ip4, ip6, vhost, port = parse_url(hosturl, eid)
                logger.debug('url parsed to: ' + repr((protocol, ip4, ip6, vhost, port)))
                parsed_urls[hosturl] = [protocol, ip4, ip6, vhost, port]
            else:
                protocol, ip4, ip6, vhost, port = parsed_urls[hosturl]

            if webappurls and zapappurl in webappurls:
                logger.debug('storing finding by webappurl ({})'.format(zapappurl))
            else:
                logger.debug('storing finding by vhost ({})'.format(vhost))
                zapappurl = vhost

            # a sanity check which should never trigger
            if vhost in hosts:
                if port in hosts[vhost]:
                    if protocol != hosts[vhost][port]['protocol']:
                        logger.error('mismatch between site and finding url protocol')
                else:
                    logger.error('mismatch between site port and finding url port')
            else:
                logger.error('host mismatch between target sites and finding url')

            ip, ipv = (ip4, 4) if ip4 else (ip6, 6)
            #res.setdefault(ip, {'ipv': ipv})

            # compile result dataset
            if ip in res:
                if port in res[ip]:
                    if zapappurl in res[ip][port]:
                        res[ip][port][zapappurl]['vhost'] = vhost
                        logger.debug('adding vhost {} to {}:{}/{}'.format(vhost, ip, port, zapappurl))
                    else:
                        res[ip][port][zapappurl] = {'vhost': vhost}
                        logger.debug('adding {}/{} to {}:{}'.format(zapappurl, vhost, ip, port))
                else:
                    res[ip][port] = {zapappurl: {'vhost': vhost}}
                    logger.debug('adding port {} to ip {}'.format(port, ip))
            else:
                res[ip] = {port: {zapappurl: {'vhost': vhost}}}
                logger.debug('adding ip to result set: {}'.format(ip))
                res[ip]['ipv'] = ipv

            proof = request_method + ' ' + request_url + '\n' + request_body
            if title in res[ip][port][zapappurl]:
                res[ip][port][zapappurl][title]['proofs'].add(proof)
                logger.debug('added proof for previously detected issue: {}'.format(proof))

            else:
                logger.debug('adding new issue: {}'.format(title))
                res[ip][port][zapappurl][title] = finding
                res[ip][port][zapappurl][title].setdefault('proofs', set()).add(proof)
                logger.debug('added proof for issue: ' + title)

    return (status, res)

def import_scan(filename, scantype, eid):
    logger.debug('importing {}'.format(filename))
    status, zap_issues = parse(filename, eid)
    if status['error']:
        return status

    conn = get_db()
    curs = conn.cursor()
    try:
        curs.execute('insert into zap_scans (engagement_id, filename, scan_type) values (%s, %s, %s) returning id',
                           (eid, filename, scantype))
        zap_id = curs.fetchone()[0]
    except psycopg2.errors.UniqueViolation as e:
        logger.info('Import failed (file already uploaded): ' + repr(e))
        status['error'] = 'Import failed. Is this file already imported?'
        conn.close()
        return status
    except Exception as e:
        logger.error(e.pgerror)
        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to store entry in zap_scans')
        status['error'] = 'Import failed'
        conn.close()
        return status

    scan_uri = 'zap/' + str(zap_id)

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
        #svc = {'sid':, 'external':, 'scan_uri_list':, 'webappurl':}
        webappurlmap[webappurl] = svc
        servicemap[host_id + '#' + port] = svc

    # compile zap issues_seen
    qry = db_getdict("select id, title, severity, fingerprint, false as updated, false as new\
                       from issues_seen where scanner = 'zap'")
    data = qry['data']
    issues_seen = {x.pop('title'): x for x in data}

    # no need to track existing findings in db, this is not summarising just adding entries to findings table

    external = True if scantype == 'external' else False
    #  res[ip][port/'ipv'][zapappurl]{'vhost': vhost, **finding}
    for ip in zap_issues:
        ipv = zap_issues[ip].pop('ipv')
        for port in zap_issues[ip]:
            for webappurl in zap_issues[ip][port]:
                # vhost is the hostname which resolves to the ip
                # webappurl may be the vhost, or the app url e.g. test.com:8000/DVWA
                vhost = zap_issues[ip][port][webappurl].pop('vhost')
                logger.debug('{}:{} {}'.format(ip, port, webappurl))
                for title in zap_issues[ip][port][webappurl]:
                    # define variables to be stored
                    logger.debug('processing: ' + title)
                    #issue = {'severity':, 'description':, 'remediation':, 'details', 'proofs': set()}
                    issue = zap_issues[ip][port][webappurl][title]

                    details = issue.pop('details')
                    if 'proofs' in issue and issue['proofs']:
                        proofs_set = issue.pop('proofs')
                        for proof in proofs_set:
                            details += '\n' + proof if details else proof

                    # variables set, figure out storage
                    # check if host exists
                    if ip in hostmap:
                        hid = hostmap[ip]
                        logger.debug('{} already exists in db'.format(ip))
                        if vhost:
                            logger.debug('trying to add vhost: {}'.format(vhost))
                            curs.execute('insert into http_virthost (host_id, virthost) values (%s, %s) on conflict do nothing',
                                                (hid, vhost))

                        #svc = {'sid':, 'external':, 'scan_uri_list':, 'webappurl':}
                        #webappurlmap[webappurl] = svc
                        #servicemap[host_id + '#' + port] = svc
                        if webappurl in webappurlmap:
                            svc = webappurlmap[webappurl]
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

                            if webappurl and not ('webappurl' in svc and svc['webappurl']):
                                update_cols.append('webappurl')
                                update_vals.append(webappurl)

                            update_vals.append(sid)
                            sql = get_pg_update_sql('services', update_cols, 'where id = %s')

                            curs.execute(sql, tuple(update_vals))

                        else:
                            logger.debug('adding new web app service at port {}'.format(port))
                            curs.execute('insert into services (host_id, protocol, port, service, webappurl, external, scan_uri_list)\
                                                        values (%s, %s, %s, %s, %s, %s, %s) returning id',
                                                               (hid, 'tcp', port, 'www', webappurl, external, scan_uri))
                            sid = curs.fetchone()[0]
                            logger.debug('updating stored data, adding {}/{}/external: {}'.format(sid, vhost, external))
                            servicemap[hid + '#' + port] = {'sid': sid, 'external': external, 'scan_uri_list': scan_uri}
                            if webappurl != vhost:
                                webappurlmap[webappurl] = {'sid': sid, 'external': external, 'scan_uri_list': scan_uri}

                    else:
                        logger.debug('keys in hostmap: ' + repr(hostmap.keys()))
                        logger.debug('adding new host and port {}:{}'.format(ip, port))
                        ipcol = 'ipv4' if ipv == 4 else 'ipv6'
                        sql = 'insert into hosts (engagement_id, ' + ipcol + ') values (%s, %s) returning id'
                        curs.execute(sql, (eid, ip))
                        hid = str(curs.fetchone()[0])
                        hostmap[ip] = hid
                        logger.debug('added host with id {}'.format(hid))

                        if vhost:
                            logger.debug('trying to add vhost: {}'.format(vhost))
                            curs.execute('insert into http_virthost (host_id, virthost) values (%s, %s) on conflict do nothing',
                                                                    (hid, vhost))

                        curs.execute('insert into services (host_id, protocol, port, service, webappurl, external, scan_uri_list)\
                                                    values (%s, %s, %s, %s, %s, %s, %s) returning id',
                                                           (hid, 'tcp', port, 'www', webappurl, external, scan_uri))
                        sid = curs.fetchone()[0]
                        logger.debug('added to stored data: {}/{}/external: {}'.format(ip, sid, external))
                        servicemap[hid + '#' + port] = {'sid': sid, 'external': external, 'scan_uri_list': scan_uri}
                        if webappurl != vhost:
                            webappurlmap[webappurl] = {'sid': sid, 'external': external, 'scan_uri_list': scan_uri}

                    # ip and service are in db, store issues
                    issue['title'] = title
                    issue['scanner'] = 'zap'
                    fingerprint = get_fingerprint(issue)
                    issue['fingerprint'] = fingerprint

                    if title in issues_seen:
                        # severity seems to be consistent for a title (not modified by confidence level)
                        if int(issues_seen[title]['severity']) != int(issue['severity']):
                            logger.warn('issue severity changed for {}'.format(title))

                        issue_seen_id = issues_seen[title]['id']
                        if fingerprint != issues_seen[title]['fingerprint']:
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
                        issue['scanner'] = 'zap'
                        cols = issue.keys()
                        vals = issue.values()
                        sql = get_pg_insert_sql('issues_seen', cols, returning='id')
                        curs.execute(sql, tuple(vals))
                        issue_seen_id = curs.fetchone()[0]
                        # this should only be needed if we ever start processing exports containing multiple scans
                        issues_seen[title] = {'id': issue_seen_id, 'fingerprint': fingerprint, 'severity': issue['severity'], 'new': True}

                    # issue details should now be stored, save findings
                    logger.debug('storing texts for issue {}'.format(title))
                    curs.execute('insert into findings (engagement_id, service_id, issue_id, scan_uri_list, vhost, external, proof)\
                                                values (%s, %s, %s, %s, %s, %s, %s)',
                                 (eid, sid, issue_seen_id, scan_uri, webappurl, external, details))

    conn.commit()
    conn.close()
    logger.debug('zap import comleted')
    return status
