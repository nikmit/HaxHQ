#!/usr/bin/env python3
import logging
import sys
import re
from defusedxml import ElementTree
from bs4 import BeautifulSoup
from inspect import currentframe, getframeinfo
from xhq.util import is_ip, get_db, db_do, db_getcol, db_getrow, db_getdict, logerror, get_fingerprint, get_pg_update_sql
from xhq.pingcastle_config import pcastle_issues, categories

logger = logging.getLogger(__name__)
logger.setLevel('INFO')
#logger.setLevel('DEBUG')

def parse(filename):
    status = {'error': False}
    res = {}
    with open(filename, 'r') as htmldata:
        logger.debug('opened ' + filename + ', parsing')
        try:
            x = BeautifulSoup(htmldata, 'lxml')
            logger.info('html content from ' + filename + ' parsed, processing data...')
        except:
            status['error'] = 'Failed to parse PingCastle HTML'


        domain_el = x.find(id='panelsectionDomainInformation')
        try:
            res['domain_name'] = domain_el.find('tbody').find('tr').find('td').get_text(strip=True).lower()
            logger.debug('scanned domain name: ' + res['domain_name'])
        except:
            status['error'] = 'Failed to determine scanned domain from PingCastle report'
            return status, None

        # check if rules maturity sections are present and fail early if not
        for n in range(1,6):
            maturitylevel = x.find(id='rulesmaturity' + str(n))
            if maturitylevel:
                container = maturitylevel.find('div', class_='card')
                logger.debug('rules maturity section detected')
                break
            else:
                continue
        else:
            status = {'error': 'Rules maturity clasification not found. Was this file generated with an old version of PingCastle?'}
            logger.warning(status['error'])
            return status, None

        try:
            oslist_table = x.find('a', attrs={'name':'operatingsystems'}).findNext('table')
        except Exception as e:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'could not find the operating systems table')
            logger.error(repr(e))
            oslist_table = None

        if oslist_table:
            res['operating_systems'] = get_table_data(oslist_table, 'oslisttable', soupisdone=True)

        if 'operating_systems' not in res:
            logger.warn('Could not extract os list table data')

        for category in categories:
            res[category] = get_table_data(x, category)

        if 'rulesmaturity3S-DC-SubnetMissing' in res:
            for dc in res['rulesmaturity3S-DC-SubnetMissing']:
                for _dc in res['domaincontrollersdetail']:
                    if _dc['Domain controller'] == dc['Domain controller']:
                        _dc['IP'] = dc['ip']

        res['anomalies'] = get_anomalies(x)

        issues = {}
        for sev in range(1,6):
            logger.debug('looking at severity ' + str(sev))
            severity_group = x.find(id='rulesmaturity' + str(sev))
            if severity_group:
                container = severity_group.find('div', class_='card')
            else:
                continue

            header_divs = container.find_all('div', class_='card-header')

            sev_map = {1:4, 2:3, 3:2, 4:1, 5:0}
            sev = sev_map[sev]
            issues[sev] = []
            for h in header_divs:
                issue = {}
                issuetag = h.get('id')[7:]      # trim the 'heading' part, leave 'rulesmaturity<n>-<titletag>
                issue['title'] = h.find('button').get_text().strip()
                content_div = container.find(id=issuetag).find('div', class_='card-body')

                for subtitle_el in content_div.find_all('strong'):
                    if not subtitle_el.parent == content_div:
                        logger.info('ignoring strong tag within text')
                        continue

                    try:
                        subtitle = subtitle_el.get_text().strip().rstrip(':')
                        logger.debug('got subtitle ' + subtitle)
                    except Exception as e:
                        status['error'] = repr(e)
                        logger.error(status['error'])
                        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to match subtitle')
                        logger.error('title: ' + issue['title'])
                    else:
                        if subtitle in ['Rule ID', 'Points', 'Details']:
                            continue
                        logger.debug('subtitle: ' + subtitle)
                        try:
                            text = subtitle_el.find_next_sibling('p').get_text().strip()
                        except Exception as e:
                            status['error'] = repr(e)
                            logerror(__name__, getframeinfo(currentframe()).lineno, 'failed extract text from subtitled section')
                            logger.error(status['error'])
                            logger.error('title: ' + issue['title'])
                        else:
                            logger.debug('text: ' + text)
                            issue[subtitle] = text

                issues[sev].append(issue)
        res['issues'] = issues

    return (status, res)

def import_scan(filename, eid):
    # pingcastle reports have to be imported after DCs have been entered in the hosts table
    # an internal nessus scan seems to get the job done
    status, data = parse(filename)
    if status['error']:
        return status

    # store in db
    conn = get_db()
    curs = conn.cursor()
    # add pingcastle scan entry
    curs.execute('insert into pingcastle_scans(engagement_id, filename) values (%s, %s) returning id', (eid, filename))
    pcid = str(curs.fetchone()[0])
    scan_uri = 'pingcastle/' + pcid

    # check for missing AD hosts and create them
    # if an IP has been seen with another DA name, just add the hostname and use the old hid and sid
    dchostmap = {}
    for i, dc in enumerate(data['domaincontrollersdetail']):
        host = None
        dc_fqdn = dc['Domain controller'].lower() + '.' + data['domain_name']
        data['domaincontrollersdetail'][i]['dc_fqdn'] = dc_fqdn
        if 'IP' in dc:
            qry = db_getrow("select id, os from hosts where engagement_id = %s and (ipv4 = %s or ipv6 = %s)",
                                    (eid, dc['IP'], dc['IP']))
            if qry['success']:
                host = qry['data']
            else:
                logger.error('query failed')

            if host:
                host['ip'] = dc['IP']
            else:
                logger.debug('dc not found in hosts table using ip ' + dc['IP'])
        else:
            # IP is only stored when DCs dont have correctly declared subnets, as part of an issue description
            qry = db_getrow('select coalesce(ipv4, ipv6) as ip, host_id, virthost, os\
                             from http_virthost join hosts on host_id = hosts.id\
                             where host_id in (select id from hosts where engagement_id = %s) and lower(virthost) = lower(%s)',
                                 (eid, dc_fqdn) )
            if qry['success']:
                vhost = qry['data']
            else:
                vhost = None
                logger.error('query failed')

            if vhost:
                host = {'id': vhost['host_id'], 'os': vhost['os'], 'ip': vhost['ip']}
                logger.debug('found hostname match: ' + vhost['virthost'] + '==' + dc_fqdn)

        # if the host matched with an existing entry in db, add the info to the data
        if host:
            logger.debug('matched dc ' + dc_fqdn + ' with host id ' + str(host['id']))
            data['domaincontrollersdetail'][i].setdefault('host_id', host['id'])
            data['domaincontrollersdetail'][i].setdefault('nessus_os', host['os'])
            dchostmap[host['ip']] = host['id']

            qry = db_getrow("select id, scan_uri_list from services where host_id = %s and protocol = 'tcp' and port = 0",
                                    (host['id'],))
            if qry['success']:
                service = qry['data']
            else:
                service = None
                logger.error('query failed')

            if service:
                data['domaincontrollersdetail'][i]['service_id'] = service['id']
                data['domaincontrollersdetail'][i]['scan_uri_list'] = service['scan_uri_list']
            else:
                logger.debug('DC seen but no tcp/0 service stored for host id ' + str(host['id']))

        else:
            logger.debug('dc ' + dc_fqdn + ' not seen before')
            if 'IP' in dc:
                # ip is in report but not matched to an existing host id
                _ip = dc['IP']
            else:
                # check if any DCs have previously had IPs auto generated
                qry = db_getcol("select max(ipv4) from hosts where engagement_id = %s and ipv4::text like '0.0.0.%%'", (eid,))
                logger.debug(repr(qry))
                # max(...) returns a list with a None item
                if qry['success'] and qry['data'] and qry['data'][0]:
                    max_dc_fake_ip = qry['data'][0]
                    # pick up the greatest number in the last octet, to ensure new IPs dont clash with existing ones
                    n = int(max_dc_fake_ip.split('.')[-1])
                    logger.debug('seen ' + str(n) + ' fake IPs for DCs')
                else:
                    n = 0

                _ip = '0.0.0.' + str(i+n+1)

            if _ip in dchostmap:
                data['domaincontrollersdetail'][i]['host_id'] = dchostmap[_ip]
                data['domaincontrollersdetail'][i].setdefault('nessus_os', None)
            else:
                logger.debug('creating dc host entry with ip ' + _ip)
                ipv = is_ip(_ip)
                curs.execute('insert into hosts (engagement_id, ipv' + str(ipv) + ', fqdn) values (%s, %s, %s) returning id',
                                (eid, _ip, dc_fqdn))
                _host_id = curs.fetchone()[0]
                dchostmap[_ip] = _host_id
                curs.execute('insert into http_virthost (host_id, virthost) values (%s, %s) on conflict do nothing',
                                (_host_id, dc_fqdn))
                data['domaincontrollersdetail'][i].setdefault('host_id', _host_id)
                data['domaincontrollersdetail'][i].setdefault('nessus_os', None)

    # compile pingcastle issues_seen
    qry = db_getdict("select id, title, severity, fingerprint from issues_seen where scanner = 'pingcastle'")
    if qry['success']:
        issues_seen = {x.pop('title'): x for x in qry['data']}
    else:
        issues_seen = {}
        logger.error('query failed')

    plugin_output = None

    ## add AD service and store findings per DC
    # if hid is same for some DCs, store and reuse values
    dcservicemap = {}       # hid: {sid: n, scan_uri_list: ''}
    for i, dc in enumerate(data['domaincontrollersdetail']):
        #dcname = dc['Domain controller']
        hid = dc['host_id']
        if hid in dcservicemap:
            # DC with this hid already seen for this import, just pick up the sid
            sid = dcservicemap[hid]['sid']
        elif 'service_id' in data['domaincontrollersdetail'][i]:
            # DC was matched to an existing host/service but not seen yet, update scan_uri_list
            sid = data['domaincontrollersdetail'][i]['service_id']
            if 'scan_uri_list' in data['domaincontrollersdetail'][i] and data['domaincontrollersdetail'][i]['scan_uri_list']:
                scan_uri_str = data['domaincontrollersdetail'][i]['scan_uri_list']
                scan_uri_set = set(scan_uri_str.split(','))
                scan_uri_set.add(scan_uri)
                scan_uri_str = ','.join(scan_uri_set)
            else:
                scan_uri_str = scan_uri
            curs.execute('update services set scan_uri_list = %s where id = %s', (scan_uri_str, sid))
            dcservicemap[hid] = {'sid': sid, 'scan_uri_list': scan_uri_str}
        else:
            # no service stored for this DC yet, add it
            scan_uri_str = scan_uri
            curs.execute('insert into services (host_id, protocol, port, service, software, scan_uri_list, external)\
                          values (%s, %s, %s, %s, %s, %s, false) returning id',
                          (dc['host_id'], 'tcp', 0, 'Domain Controller', dc['FSMO role'], scan_uri_str))
            sid = curs.fetchone()[0]
            dcservicemap[hid] = {'sid': sid, 'scan_uri_list': scan_uri_str}

        # every issue is entered for every DC, for consistency with nessus imports
        # if database size becomes a problem, savings could be made here
        new_issues = []
        for severity in data['issues']:
            _seen = False
            for issue in data['issues'][severity]:
                title = issue['title']
                logger.debug('processing: ' + title)
                for pcissue in pcastle_issues:
                    pctitle = pcissue['title']
                    if title.startswith(pctitle) or title.endswith(pctitle):
                        plugin_output = 'Original title: ' + title
                        title = pctitle

                logger.debug('storing as: ' + title)

                description = issue['Description'] + '\n' + issue['Technical explanation']
                remediation = issue['Advised solution']
                see_also = issue['Documentation'] if 'Documentation' in issue else None

                # store or update issues_seen as needed
                # check if the issue exists and whether scanner texts have been updated
                #XXX issue is rewritten below better to use different vars to avoid confusion
                issue = {'title': title, 'description': description, 'remediation': remediation, 'severity': severity}
                if see_also:
                    issue['see_also'] = see_also
                else:
                    logger.debug('no documentation for: ' + issue['title'])

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
                            status['error'] = e.pgerror
                            logger.error(status['error'])
                            logerror(__name__, getframeinfo(currentframe()).lineno, 'insert failed')
                            return status

                        issues_seen[title]['fingerprint'] = fingerprint
                else:
                    logger.info('adding new issue: ' + title)
                    issue['scanner'] = 'pingcastle'
                    cols = issue.keys()
                    vals = issue.values()
                    placeholders = '%s,'*(len(cols) - 1) + '%s'
                    sql = 'insert into issues_seen (' + ','.join(cols) + ') values (' + placeholders + ') returning id'
                    curs.execute(sql, tuple(vals))
                    issue_seen_id = curs.fetchone()[0]
                    issues_seen[title] = {'id': issue_seen_id, 'fingerprint': fingerprint, 'severity': severity}

                # issues_seen stored/updated
                # collect proofs for issues
                details = ''
                for pcissue in pcastle_issues:
                    key = pcissue['title']
                    if title.startswith(key) or title.endswith(key):
                        _seen = True

                        if pcissue['storenames']:
                            logger.debug('getting details for ' + key)
                            for storename in pcissue['storenames']:
                                if storename not in data or not data[storename]:
                                    logger.debug('no data collected from storename ' + storename)
                                    continue

                                if storename == 'anomalies':
                                    #{'Last backup date': '2023-01-08 21:53:13Z', 'LAPS installation date': '2017-03-02 11:42:28Z',
                                    #'Number of WEF configuration found': '0', 'Kerberos password last changed': '2016-10-08 09:51:16Z',
                                    #'Number of accounts to review': '0', 'Java Schema extension': 'Not Found' }
                                    label = pcissue['sourcecols'][0]
                                    details += label + ': ' + data['anomalies'][label]

                                else:
                                    sourcecols = pcissue['sourcecols'] if pcissue['sourcecols'] else data[storename][0].keys()
                                    check = pcissue['check']
                                    col2check = pcissue['col2check']
                                    logger.debug('storename is ' + storename)
                                    for entry in data[storename]:
                                        logger.debug('entry is ' + repr(entry))
                                        if not check or check(entry[col2check]):
                                            logger.debug('no check or check passed')
                                            templist = []
                                            for label in sourcecols:
                                                logger.debug('got value for label ' + label + ': ' + entry[label])
                                                # drop the label if a single column
                                                if len(sourcecols) > 1:
                                                    templist.append(label + ': ' + entry[label])
                                                else:
                                                    templist.append(entry[label])
                                            details += '\n' + ', '.join(templist)
                        break

                proof = details.strip() if details else None
                #if proof:
                #    logger.debug('#' + proof)
                curs.execute("insert into findings (engagement_id, service_id, issue_id, proof, external, plugin_output, scan_uri_list)\
                              values (%s, %s, %s, %s, false, %s, %s)",
                    (eid, sid, issue_seen_id, proof, plugin_output, scan_uri))

                if not _seen:
                    logger.warning('Pingcastle key missing in pingcastle_config: ' + title)
                    new_issues.append(title)

        # update nessus-detected OS if needed
        if dc['Operating System'] and dc['nessus_os'] != dc['Operating System']:
            curs.execute('update hosts set os = %s where id = %s', (dc['Operating System'], dc['host_id']))
            logger.debug('pingcastle detected different OS than nessus, updated record from ' + str(dc['nessus_os']) + ' to ' + str(dc['Operating System']))

    conn.commit()
    curs.close()

    if new_issues:
        # a list of pingcastle finding titles, not linkable to ip addresses or domains
        # pingcastle reports change often and changes in titles require updates
        logerror(__name__, getframeinfo(currentframe()).lineno, repr(new_issues))

    return status

def get_anomalies(soup):
    '''extract anomalies list
       should return {'Last backup date': '2023-01-08 21:53:13Z', 'LAPS installation date': '2017-03-02 11:42:28Z',
                      'Number of WEF configuration found': '0', 'Kerberos password last changed': '2016-10-08 09:51:16Z',
                      'Number of accounts to review': '0', 'Java Schema extension': 'Not Found' }
       only backup and kerberos values are used currently, adminsdholder table is retrieved separately'''
    anomalies = {}
    anomalies_div = soup.find('div', id='panelsectionAnomalies')
    if anomalies_div:
        for cdiv in anomalies_div.find_all('div', class_='col-lg-12'):
            for p in cdiv.find_all('p'):
                if p.find('strong'):
                    key, value = None, None
                    for s in p.strings:
                        if not key:
                            key = s.strip(' :')
                        elif not value:
                            value = s.strip()

                        anomalies[key] = value

    return anomalies

def get_table_data(soup, containerid, soupisdone=False):
    '''extract data from tables within reports'''
    result = []
    container = soup if soupisdone else soup.find('div', id=containerid)
    if container:
        cols = [th.get_text(strip=True).strip('?') for th in container.find_all('th')]
        for tr in container.find('tbody').find_all('tr'):
            values = [td.get_text(strip=True).strip('?') for td in tr.find_all('td')]
            entry = dict(zip(cols, values))
            result.append(entry)

        if result:
            logger.debug('extracted details from table in ' + containerid)
        else:
            logger.warn('container matched but nothing extracted: ' + containerid)
        #logger.debug(repr(result))
    else:
        logger.debug('container not found: ' + containerid)

    return result

def get_name_by_attr(listofdicts, col2return, targetcol, targetvalue):
    res = []
    for item in listofdicts:
        if targetcol in item and item[targetcol] == targetvalue:
            res.append(item[col2return])

    return res

def checktags(categories, taglist):
    with open (taglist, 'r') as tags:
        yeslist = []
        nolist = []
        for tag in tags:
            tag = tag.strip()
            if tag in categories:
                continue

            try:
                test = get_table_data(x, tag)
                if test:
                    yeslist.append(tag)
            except:
                nolist.append(tag)

        print('yes:')
        for tag in yeslist:
            print(tag)
        print('no:')
        for tag in nolist:
            print(tag)

def parse_schema():
    ''' opens /srv/pingcastle/Healthcheck/Rules/RuleDescription.resx and imports issue titles to pingcastle_config '''

    filename = '/srv/pingcastle/Healthcheck/Rules/RuleDescription.resx'
    status = {'error': False}
    try:
        tree = ElementTree.parse(filename)
    except Exception as e:
        status['error'] = repr(e)
        logerror(__name__, getframeinfo(currentframe()).lineno, status['error'])

        return (status, None)

    root = tree.getroot()
    for el in root.findall('data'):
        if el.get('name').endswith('_Rationale'):
            title = el.find('value').text
            matched_count = 0
            for pcissue in pcastle_issues:
                key = pcissue['title']
                if title.startswith(key) or title.endswith(key):
                    if matched_count:
                        print('WARNING: ' + title)
                        print('WARNING: ' + key)
                    elif len(title) > (len(key) + 16):
                        print('INFO: ' + title)
                        print('INFO: ' + key)

                    matched_count += 1
            else:
                pass
                #if not matched_count:
                #    print("{'title': '" + title + "', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },")
