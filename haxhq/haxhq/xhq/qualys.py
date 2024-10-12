#!/usr/bin/env python3
import logging
import warnings
from bs4 import BeautifulSoup
from bs4 import MarkupResemblesLocatorWarning
from inspect import currentframe, getframeinfo
from defusedxml import ElementTree
from xhq.util import is_ip, get_db, db_getcol, db_getrow, db_getdict, checklink, logerror, get_fingerprint

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

logger = logging.getLogger(__name__)
logger.setLevel('INFO')
logger.setLevel('DEBUG')

def import_scan(filename, scantype, eng_id):
    status, data = parse(filename, eng_id)
    if not status['error']:
        status = store_db(filename, scantype, eng_id, data)

    return status

def parse(filename, eng_id):
    status = {'error': False}
    result = {}
    links_checked = {}
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
    vuln_map = {}
    try:
        vuln_list = root.find('GLOSSARY').find('VULN_DETAILS_LIST').findall('VULN_DETAILS')
    except Exception as e:
        status['error'] = 'Unexpected XML structure: could not find VULN_DETAILS tag'
        logerror(__name__, getframeinfo(currentframe()).lineno, status['error'])
        return status, None

    for vuln in vuln_list:
        vid = vuln.find('QID').text
        title = vuln.find('TITLE').text.strip()
        severity = int(vuln.find('SEVERITY').text) - 1
        category = vuln.find('CATEGORY').text.strip()
        description = BeautifulSoup(vuln.find('THREAT').text, 'lxml').get_text(' ', strip=True)
        impact = BeautifulSoup(vuln.find('IMPACT').text, 'lxml').get_text(' ', strip=True)
        solution = BeautifulSoup(vuln.find('SOLUTION').text, 'lxml').get_text(' ', strip=True)
        pci_flag = vuln.find('PCI_FLAG').text
        last_update = vuln.find('LAST_UPDATE').text.strip()

        vuln_map.setdefault(vid, {'title': title, 'severity': severity, 'category': category, 'description': description,
                                  'impact': impact, 'solution': solution, 'pci_flag': pci_flag, 'last_update': last_update})

        try:
            compliance = vuln.find('COMPLIANCE').find('COMPLIANCE_INFO')
        except:
            compliance = None
            logger.debug('no compliance data for ' + vid)

        if compliance:
            compliance_type = compliance.find('COMPLIANCE_SECTION').text.strip()
            compliance_desc = compliance.find('COMPLIANCE_DESCRIPTION').text.strip()
            vuln_map[vid].setdefault('compliance', {'type': compliance_type, 'description': compliance_desc})

        try:
            cve_list = vuln.find('CVE_ID_LIST').findall('CVE_ID')
        except:
            cve_list = None
            logger.debug('no cves for ' + vid)

        if cve_list:
            vuln_map[vid].setdefault('cve_list', [])
            for cve in cve_list:
                cve_id = cve.find('ID').text.strip()
                cve_url = cve.find('URL').text.strip()
                vuln_map[vid]['cve_list'].append({'id': cve_id, 'url': cve_url})

        try:
            vendor_ref_list = vuln.find('VENDOR_REFERENCE_LIST').findall('VENDOR_REFERENCE')
        except:
            vendor_ref_list = None
            logger.debug('no cves for ' + vid)

        if vendor_ref_list:
            vuln_map[vid].setdefault('vendor_ref_list', [])
            for ref in vendor_ref_list:
                ref_id = ref.find('ID').text.strip()
                ref_url = ref.find('URL').text.strip()
                #if ref_url not in links_checked:
                #    links_checked.setdefault(ref_url, checklink(ref_url))
                #if links_checked[ref_url]:
                vuln_map[vid]['vendor_ref_list'].append({'id': ref_id, 'url': ref_url})

        try:
            correlation = vuln.find('CORRELATION')
        except:
            correlation = None
            logger.debug('no correlation section for: ' + title)

        if correlation:
            try:
                explt_sources = correlation.find('EXPLOITABILITY').findall('EXPLT_SRC')
            except:
                explt_sources = None

            if explt_sources:
                vuln_map[vid].setdefault('explt_sources', {})
                for explt_src in explt_sources:
                    name = explt_src.find('SRC_NAME').text.strip()
                    vuln_map[vid]['explt_sources'].setdefault(name, [])
                    explt_list = explt_src.find('EXPLT_LIST').findall('EXPLT')
                    for explt in explt_list:
                        cve = explt.find('REF').text.strip()
                        desc = explt.find('DESC').text.strip()
                        link = explt.find('LINK').text.strip()
                        if desc or link:
                            vuln_map[vid]['explt_sources'][name].append({'cve': cve, 'desc': desc, 'link': link})

            try:
                malware_sources = correlation.find('MALWARE').findall('MW_SRC')
            except:
                malware_sources = None
                logger.debug('no malware sources in correlation section for: ' + title)

            if malware_sources:
                vuln_map[vid].setdefault('mw_sources', {})
                for mw_src in malware_sources:
                    name = mw_src.find('SRC_NAME').text.strip()
                    vuln_map[vid]['mw_sources'].setdefault(name, [])
                    mw_list = mw_src.find('MW_LIST').findall('MW_INFO')
                    for mw in mw_list:
                        mwid = mw.find('MW_ID').text.strip()
                        mwtype = mw.find('MW_TYPE').text.strip()
                        mw_platform = mw.find('MW_PLATFORM')
                        platform = mw_platform.text.strip() if mw_platform else ''
                        vuln_map[vid]['mw_sources'][name].append({'id': mwid, 'type': mwtype, 'platform': platform})
        else:
            logger.debug('no correlation section for: ' + title)

    host_list = root.find('HOST_LIST').findall('HOST')
    for host in host_list:
        ip = host.find('IP').text
        os = host.find('OPERATING_SYSTEM').text.strip()
        hostname = host.find('DNS').text.strip()
        netbios = host.find('NETBIOS').text.strip()

        result.setdefault(ip, {'os': os, 'hostname': hostname, 'vulns': []})
        vuln_list = host.find('VULN_INFO_LIST').findall('VULN_INFO')
        for vuln in vuln_list:
            vid = vuln.find('QID').text
            proof = vuln.find('RESULT').text.strip()
            result[ip]['vulns'].append(vuln_map[vid] | {'proof': proof, 'vid': vid})


    return status, result

def store_db(filename, scantype, eng_id, data):
    logger.info('storing qualys scan')
    status = {'error': False}
    conn = get_db()
    curs = conn.cursor()
    try:
        curs.execute('insert into qualys_scans (engagement_id, filename, scan_type) values (%s, %s, %s) returning id',
                               (eng_id, filename, scantype))
        scanid = str(curs.fetchone()[0])
    except psycopg2.errors.UniqueViolation as e:
        logger.warn('Import failed: ' + repr(e))
        status['error'] = 'Import failed. Is this file already imported?'
        return status
    except Exception as e:
        logger.error(e.pgerror)
        logerror(__name__, getframeinfo(currentframe()).lineno, 'query failed')
        status['error'] = 'Import failed'
        return status

    # compile qualys issues_seen
    qry = db_getdict("select id, title, severity, fingerprint from issues_seen where scanner = 'qualys'")
    if qry['success']:
        issues_seen = {x.pop('title'): x for x in qry['data']}
    else:
        issues_seen = {}
        logger.error('query failed')

    scan_uri = 'qualys/' + scanid
    isexternal = True if scantype == 'external' else False
    for ip in data:
        # check host exists in hosts table, add entry if needed
        qry = db_getrow('select id from hosts where engagement_id = %s and (ipv4 = %s or ipv6 = %s)',
                              (eng_id, ip, ip))
        host = qry['data']
        if host:
            hostid = host['id']
            logger.debug('adding virthost for host id ' + str(hostid))
            curs.execute('insert into http_virthost (host_id, virthost) values (%s, %s) on conflict do nothing',
                              (hostid,data[ip]['hostname']))
            curs.execute('update hosts set os = %s where id = %s', (data[ip]['os'], hostid))

            qry = db_getrow("select id, scan_uri_list from services where host_id = %s and protocol = 'tcp' and port = 0",
                                     (hostid,))
            service = qry['data']
            if service:
                serviceid = service['id']
                scan_uri_set = set(service['scan_uri_list'].split(',')) if service['scan_uri_list'] else set()
                scan_uri_set.add(scan_uri)
                scan_uri_str = ','.join(scan_uri_set)
                curs.execute('update services set scan_uri_list = %s where id = %s', (scan_uri_str, serviceid))
            else:
                curs.execute("insert into services (host_id, protocol, port, external, scan_uri_list)\
                                            values (%s, 'tcp', 0, %s, %s) returning id",
                                            (hostid, isexternal, scan_uri))
                serviceid = curs.fetchone()[0]
        else:
            # check address type and store host entry
            ipv = is_ip(ip)
            if ipv:
                curs.execute('insert into hosts (engagement_id, ipv' + str(ipv) + ', os) values (%s, %s, %s) returning id',
                              (eng_id, ip, data[ip]['os']))
                hostid = curs.fetchone()[0]
                curs.execute('insert into http_virthost (host_id, virthost) values (%s, %s) on conflict do nothing',
                              (hostid,data[ip]['hostname']))
                curs.execute("insert into services (host_id, protocol, port, external, scan_uri_list)\
                                            values (%s, 'tcp', 0, %s, %s) returning id",
                                            (hostid, isexternal, scan_uri))
                serviceid = curs.fetchone()[0]

        for vuln in data[ip]['vulns']:
            title = vuln['title']
            severity = vuln['severity']
            issue = { x: vuln[x] for x in ['title', 'description', 'severity', 'impact'] }
            issue['remediation'] = vuln['solution']
            finding = {'engagement_id': eng_id, 'service_id': serviceid, 'scan_uri_list': scan_uri, 
                       'external': isexternal, 'proof': vuln['proof']}

            if 'cve_list' in vuln:
                cve_list = []
                ref_list = []
                for cve in vuln['cve_list']:
                    cve_list.append(cve['id'])
                    ref_list.append(cve['url'])

                issue['cve'] = ','.join(cve_list)
                finding['plugin_output'] = ','.join(ref_list)

            if 'explt_sources' in vuln:
                explt_list = []
                for src_name in vuln['explt_sources']:
                    for explt in vuln['explt_sources'][src_name]:
                        explt_list.append(explt['desc'] + '\n' + explt['link'] + '\n')

                issue['exploitability_ease'] = '\n'.join(explt_list)
                issue['exploit_available'] = True

            if 'vendor_ref_list' in vuln:
                issue['see_also'] = ','.join([x['url'] for x in vuln['vendor_ref_list']])

            # check if the issue exists and whether scanner texts have been updated
            fingerprint = get_fingerprint(issue)
            issue['fingerprint'] = fingerprint
            if title in issues_seen:
                # in all cases, set issue_seen_id
                issue_seen_id = issues_seen[title]['id']
                # if fingerprints don't match, update
                if fingerprint != issues_seen[title]['fingerprint']:
                    logger.info('issue seen but is changed, updating: ' + title)
                    cols = issue.keys()
                    vals = list(issue.values())
                    sql = get_pg_update_sql('issues_seen', cols, 'where id = %s')
                    vals.append(issue_seen_id)

                    try:
                        curs.execute(sql, tuple(vals))
                    except Exception as e:
                        status['error'] = e.pgerror
                        logger.warn(status['error'])
                        logger.debug(sql)
                        logger.debug(repr(vals))
                        return status

                    # this is probably redundant but shouldn't hurt
                    issues_seen[title]['fingerprint'] = fingerprint
            else:
                logger.info('adding new issue: ' + title)
                issue['scanner'] = 'qualys'
                cols = issue.keys()
                vals = issue.values()
                placeholders = '%s,'*(len(cols) - 1) + '%s'
                sql = 'insert into issues_seen (' + ','.join(cols) + ') values (' + placeholders + ') returning id'
                curs.execute(sql, tuple(vals))
                issue_seen_id = curs.fetchone()[0]
                # this should only be needed if we ever start processing exports containing multiple scans
                issues_seen[title] = {'id': issue_seen_id, 'fingerprint': fingerprint, 'severity': severity}

            # issue details should now be stored, save findings
            finding['issue_id'] = issue_seen_id

            # malware data not currently used, seems too vague to be useful
            # save to db
            cols = finding.keys()
            vals = finding.values()
            placeholders = '%s,'*(len(cols) - 1) + '%s'
            curs.execute('insert into findings (' + ', '.join(cols) + ') values (' + placeholders + ')', tuple(vals))

    try:
        conn.commit()
    except Exception as e:
        logger.error(e.pgerror)
        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to commit qualys import')
        status['error'] = 'Import failed'
        conn.close()
        return status

    curs.close()

    return status
