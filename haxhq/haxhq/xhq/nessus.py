#!/usr/bin/env python3
import re
import sys
import time
import copy
import logging
import psycopg2.extras
from inspect import currentframe, getframeinfo
from defusedxml import ElementTree
from decimal import Decimal
from xhq.util import is_ip, get_db, db_do, db_copy, db_getcol, db_getrow, db_getdict, remove_repeat_whitespace, logerror, get_fingerprint, get_pg_update_sql, get_longest_match
from xhq.nessus_config import info_plugins, report_item_tags, informational_as_issue, ignore_plugins

logger = logging.getLogger(__name__)
logger.setLevel('INFO')
#logger.setLevel('DEBUG')

#NOTE unless the table is in the list below, no data will be saved to it
tables = ['nessus_scans', 'hosts', 'services', 'findings', 'nessus_errors', 'http_virthost']

def get_table_fields(table):
    '''returns a list of the column names in the passed table but excludes 'id' and 'notes' '''
    qry = db_getcol("select attname as col \
                     from pg_attribute \
                     where attrelid = 'public."+table+"'::regclass \
                        and attnum > 0 and not attisdropped \
                        and attname not in ('id', 'notes')")

    if not qry['data']:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to get table fields for ' + table)
        return False
    else:
        return qry['data']

def process_vuln(item):
    # protocol -> port -> severity -> [ title -> params ]
    protocol = item.get('protocol')
    port = item.get('port')
    try:
        svc_name = item.get('svc_name')
    except:
        svc_name = None

    title = item.get('pluginName')
    # nessus can report two issues with same title and differing severities, e.g. Apache < 2.4.49 Multiple Vulnerabilities
    # capture the pluginID to distinguish between updated issues and this stupidity
    plugin_id = item.get('pluginID')
    vuln = { 'title': title, 'plugin_id': plugin_id }
    # no service name col in findings table - need a mechanism to update services from findings info
    # when portscan fails to complete service info not being picked up?

    for child in item.findall('./'):
        tag = child.tag
        if tag in report_item_tags:
            #logger.debug('parsing tag ' + tag)
            key = 'cvss3' if tag == 'cvss3_base_score' else tag
            vuln.setdefault(key, child.text.strip().replace('     ', ' '))
        #else:
            #logger.debug('ignored tag ' + tag)

    return (protocol, port, svc_name, vuln)

def process_info(item):
    # need to return (protocol, port, data)
    plugin = item.get('pluginName')
    if plugin in ignore_plugins:
        return None
    elif plugin in info_plugins.keys():
        logger.debug('Plugin processing: parsing as special item (' + plugin + ')')
        # get settings for the plugin determining e.g. what part of the xml contains the interesting value and where to store it
        el = info_plugins[plugin]
        protocol = item.get('protocol')
        port = item.get('port')
        # either tag or value should always be defined in nessus_config.py for anything in info_plugins
        # sometimes target container is empty
        if 'tag' in el.keys():
            # this normally looks for the plugin_output tag
            try:
                container = item.find(el['tag'])
                val = container.text.strip() if container.text else 'N/A'
                logger.debug('checking tag ' + el['tag'] + ' got value ' + val)
            except:
                frameinfo = getframeinfo(currentframe())
                filename = frameinfo.filename.split('/')[-1]
                logger.error('parse error: ' + filename + ':' + str(frameinfo.lineno))
        elif 'value' in el.keys():
            val = el['value']
        else:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'misconfigured nessus_config.py - no tag or value -' + plugin)

        if 're' in el:
            logger.debug('applying regexp: ' + el['re'])
            info = ',\n'.join([i.strip() for i in re.findall(el['re'], val, flags=re.MULTILINE)])
            if not info:
                logger.debug('applied regexp: ' + el['re'])
                logger.debug('no match in: ' + repr(val))
            else:
                logger.debug('regexp produced: ' + repr(info))
        else:
            info = val

        if 'prefix' in el:
            info = el['prefix'] + info

        # virthost and bad_rdns can be attached to host directly
        if plugin == 'Additional DNS Hostnames':
            return { 'host': { 'virthost': re.findall(el['re'], val, flags=re.MULTILINE) }}
        elif plugin == 'Inconsistent Hostname and IP Address':
            logger.debug('extracting bad_fqdn from ' + info)
            #NOTE with multiple such records the last will clobber the preceding
            return {'host': { 'bad_fqdn': info }}
        elif el['yields'] and el['yields'].startswith('hosts'):
            logger.debug(plugin + ' : ' + repr({ el['key']: info}))
            return { 'host': { el['key']: info} }
            #else:
            #    if el['key'] == 'virthost':
            #    return { 'host': { el['key']: info }}
        # rest of plugins yield service info
        else:
            logger.debug('service info plugin')
            #sitemap can be very noisy, filter out manuals
            if plugin == 'Web Application Sitemap':
                info = re.sub(r'^https?://(?:[a-z0-9\.-]+/)+(?:manual|help)/[a-z0-9-]+/.*[\r\n]*', '', info, flags=re.MULTILINE)
            # the port/service provided for this is 0/general, correct data has to be extracted from output
            elif plugin == 'Open Port Re-check':
                tmp = re.findall(r'Port (\d+) .*', info)
                # occasionally this plugin runs for an empty list of ports?
                if tmp:
                    port = tmp[0]
                else:
                    return None
            # filter out duplicates and issuer names
            elif plugin == 'SSL Certificate Information':
                uniq = set(info.split(',\n'))
                info = ','.join(uniq)
            # the Drupal and PHP below need to be stored in db rather than added at query time to simplify the filtering
            # add Drupal to info
            elif plugin == 'Drupal Software Detection':
                info = remove_repeat_whitespace(info)
                info = re.sub(r'\bVersion\b', 'Drupal Version', info)

            # the relevant column name in services table
            key = el['key']

            logger.debug('plugin returning: ' + repr({'protocol': protocol, 'port': port, 'service': {key: info}}))
            return {'protocol': protocol, 'port': port, 'service': {key: info}}

    else:
        logger.warning('unknown plugin, ignoring: ' + plugin)
        if plugin in unhandled_plugins:
            unhandled_plugins[plugin] += 1
        else:
            unhandled_plugins.setdefault(plugin, 1)
        return None

def process_desc(description_text, category, existing_data=None):
    # just looking for desctiption, rationale and impact text in here, may extract more if needed
    wanted = {'description': [], 'rationale': [], 'impact': [], 'default_text': []}
    res = {}

    headings = ['Rationale:', 'Solution:', 'Impact:', 'Default Value:', 'See Also:', 'Reference:', 'Policy Value:', 'Actual Value:']
    current_heading = None
    # parse the current text blob
    for line in description_text.splitlines():
        line = line.strip()
        if line:
            if line in headings:
                current_heading = line[:-1].lower()
                logger.debug('set current heading to: ' + current_heading)
            else:
                if current_heading in wanted:
                    wanted[current_heading].append(line)
                    logger.debug('appended to ' + current_heading + ': ' + line)
                elif not current_heading:
                    wanted['default_text'].append(line)
                else:
                    logger.debug('ignoring, category not wanted: ' + current_heading + '/' + line)

    if category in wanted:
        wanted[category] += wanted.pop('default_text')
    else:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'the passed category is not in the wanted list: ' + str(category))

    # merge the results from parsing the current text with any existing data
    if existing_data:
        #print('#### existing data: ' + repr(existing_data))
        for tag in wanted:
            if existing_data[tag]:
                for line in wanted[tag]:
                    if line in existing_data[tag]:
                        logger.debug('exists: ' + line)
                    else:
                        existing_data[tag].append(line)
                res.setdefault(tag, existing_data[tag])
            else:
               res.setdefault(tag, wanted[tag])
    else:
        res = wanted

    return res

def process_csa(host):
    # handle cloud infrastructure scans
    #cloud_providers = ['Amazon AWS', 'Microsoft Azure', 'Office 365', 'Rackspace', 'Salesforce.com']
    name = host.get('name')
    if name and (name != '127.0.0.1' and name != 'localhost'):
        # check if any cloud IPs are already auto generated
        qry = db_getcol("select max(ipv4) from hosts where engagement_id = %s and ipv4::text like '0.0.0.%%'", (eid,))
        max_fake_ip = qry['data']
        if max_fake_ip and max_fake_ip[0]:
            # if yes, pick up the greatest number in the last octet, to ensure any new IPs generated dont clash with existing ones
            n = int(max_fake_ip[0].split('.')[-1])
            logger.debug('seen ' + str(n) + ' fake IPs for cloud providers')
        else:
            n = 0

        res = {'ipv4': '0.0.0.' + str(n + 1), 'service_name': name, 'tcp': {'0': {}}}
    else:
        return None

    ri_list = host.findall('ReportItem')
    for ri in ri_list:
        try:
            check_name = ri.find('{http://www.nessus.org/cm}compliance-check-name').text.strip()
        except:
            # the nessus scan information report item doesn't have check name
            if ri.get('pluginName') == "Nessus Scan Information":
                continue
            else:
                logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to find compliance check name')
                return None

        result = ri.find('{http://www.nessus.org/cm}compliance-result').text.strip()

        try:
            solution = ri.find('{http://www.nessus.org/cm}compliance-solution').text.strip()
        except:
            logger.warning('found no csa solution section')
            solution = ''

        try:
            reference = ri.find('{http://www.nessus.org/cm}compliance-see-also').text.strip()
        except:
            logger.warning('found no csa references section')
            reference = ''

        try:
            policy_value = ri.find('{http://www.nessus.org/cm}compliance-policy-value').text.strip()
        except:
            logger.warning('found no policy value')
            policy_value = None

        try:
            actual_value = ri.find('{http://www.nessus.org/cm}compliance-actual-value').text.strip()
        except:
            logger.warning('found no compliance actual value')
            actual_value = None

        # extract description, rationale, impact data from the text blob in description and compliance-info tags
        dri_data = None
        try:
            # check the text blob under description
            description_text = ri.find('description').text.strip()
        except:
            description_text = None
            logger.warn('found no csa description section')
        if description_text:
            # pass the default category for text
            dri_data = process_desc(description_text, 'description')
        try:
            # check the text blob under compliance-info
            compliance_info = ri.find('{http://www.nessus.org/cm}compliance-info').text.strip()
        except:
            compliance_info = None
            logger.warn('found no csa compliance info section')
        if compliance_info:
            dri_data = process_desc(compliance_info, 'description', existing_data=dri_data)

        try:
            audit_file = ri.find('{http://www.nessus.org/cm}compliance-audit-file').text.strip()
        except:
            audit_file = None
            logger.info('found no csa cimpliance-audit-file tag')

        try:
            benchmark = ri.find('{http://www.nessus.org/cm}compliance-benchmark-name').text.strip()

            _match = re.search(r'\s(E\d)\s', benchmark)
            if _match:
                audit_level = _match[1]
            else:
                _match = re.search(r'\s(E\d)$', benchmark)
                if _match:
                    control_set = _match[1]
                logger.warning('No En value in: ' + benchmark)
                audit_level = None

            _match = re.search(r'\s(L\d|Level_\d)\s', benchmark)
            if _match:
                control_set = _match[1]
            else:
                _match = re.search(r'\s(L\d|Level_\d)$', benchmark)
                if _match:
                    control_set = _match[1]
                else:
                    logger.warning('No Ln value in: ' + benchmark)
                    control_set = None
        except:
            logger.warning('no benchmark info found')
            audit_level, control_set = (None, None)

        description = '\n'.join(dri_data['description']) if dri_data and dri_data['description'] else ''
        rationale = '\n'.join(dri_data['rationale']) if dri_data and dri_data['rationale'] else ''
        impact = '\n'.join(dri_data['impact']) if dri_data and dri_data['rationale'] else ''

        csa_issue = {'title': check_name, 'benchmark': benchmark, 'compliance': result,\
                     'description': description, 'rationale': rationale, 'impact': impact, 'reference': reference,\
                     'solution': solution, 'audit_level': audit_level, 'control_set': control_set, 'audit_file': audit_file,
                     'policy_value': policy_value, 'actual_value': actual_value}
        res['tcp']['0'].setdefault(result, [])
        res['tcp']['0'][result].append(csa_issue)
        #print(check_name + ': ' + audit_level + '/' + control_set)

    fails = len(res['tcp']['0']['FAILED']) if 'FAILED' in res['tcp']['0'] else 0
    warns = len(res['tcp']['0']['WARNING']) if 'WARNING' in res['tcp']['0'] else 0
    passes = len(res['tcp']['0']['PASSED']) if 'PASSED' in res['tcp']['0'] else 0
    logger.debug('parsed csa issues. fail: ' + str(fails) + ', warn: ' + str(warns) + ', pass: ' + str(passes))

    return res

def process_host(host):
    res = {'vhost_list': []}
    status = {'error': False}

    # this is defined if the nessus target is specified by hostname
    report_host_name = host.get('name')
    # stadard nessus scans provide no request info for web app vulns
    # webappurl is kinda fake here, need to test and consider removing
    webappurl = report_host_name if not is_ip(report_host_name) else None
    if webappurl:
        logger.debug('set webappurl to ' + webappurl)

    hprops = host.find('HostProperties').findall('tag')
    if hprops:
        for tag in hprops:
            name = tag.get('name')
            if name == 'os':
                os = tag.text.strip()
                res['os'] = os if os != 'other' else None
            elif name == 'host-rdns':
                rdns = tag.text.strip()
                res['rdns'] = rdns if is_ip(rdns) else None
            elif name == 'host-fqdn':
                vhost = tag.text.strip()
                res['fqdn'] = vhost
                res['vhost_list'].append(vhost)
                # if target host is defined with a hostname, record it as webappurl

            elif name == 'host-ip':
                ip = tag.text.strip()
                v = is_ip(ip)
                if v == 4:
                    res.setdefault('ipv4', ip)
                elif v == 6:
                    res.setdefault('ipv6', ip)
                else:
                    logger.warning('value provided in host-ip tag not recognised as an IP (' + ip + ')')

            elif name == 'operating-system':
                res['os_detail'] = tag.text.strip()

    else:
        logger.warn('no host properties, is this a mishandled CSA scan?')

    if ('ipv4' in res and res['ipv4']) or ('ipv6' in res and res['ipv6']):
        #logger.debug('collected base info for host ' + repr(res))
        pass
    else:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'could not get ip address for host')
        logger.error('could not get ip address for host: ' + repr(host))
        status['error'] = 'could not get ip address for at least one host in scan'
        return (status, None)

    for ri in host.findall('ReportItem'):
        plugin = ri.get('pluginName')
        severity = ri.get('severity')
        logger.debug('severity: ' + str(severity) + ', ' + plugin)
        #res.setdefault('plugin_set', set()).add(plugin)

        # the severity parameter in the xml has become unreliable, reporting severity levels that don't correspond to CVSS values
        # if cvss data exists, override it, preferring CVSSv3
        cvss3_tag = ri.find('cvss3_base_score')
        cvss_tag = ri.find('cvss_base_score')

        cvss_map = { 9: '4', 7: '3', 4: '2', 1: '1' }

        if cvss3_tag is not None:
            cvss3 = int(Decimal(cvss3_tag.text.strip()))
            for n in [9, 7, 4, 1]:
                if cvss3 >= n:
                    severity = cvss_map[n]
                    logger.debug('mapped cvss3 ' + str(cvss3) + ' to ' + severity + ' (' + plugin + ')')
                    break
        elif cvss_tag is not None:
            cvss = int(Decimal(cvss_tag.text.strip()))
            for n in [9, 7, 4, 1]:
                if cvss >= n:
                    severity = cvss_map[n]
                    logger.debug('mapped cvss ' + str(cvss) + ' to ' + severity)
                    break
        else:
            logger.debug('no cvss/3 tag in ' + plugin)

        if int(severity) or plugin in informational_as_issue:
            logger.debug('Plugin processing: parsing vuln: ' + plugin + ' [severity: ' + severity + ']')
            protocol, port, svc_name, vuln = process_vuln(ri)
            if plugin == 'TCP Port 0 Open: Possible Backdoor':
                svc_name = None

            if svc_name in ['www', 'http?', 'https?'] and not webappurl and 'fqdn' in res and res['fqdn']:
                logger.debug('setting webappurl for www service from fqnd' + res['fqdn'])
                webappurl = res['fqdn']
            #TODO not all web applications are picked up by nessus with these svc_name values
            elif svc_name not in ['www', 'http?', 'https?'] and webappurl:
                logger.debug('service other than www, clearing webappurl ' + webappurl)
                webappurl = None

            if protocol not in res:
                res[protocol] = {port: {webappurl: {severity: [], 'service': svc_name, 'external': external}}}
            elif port not in res[protocol]:
                res[protocol][port] = {webappurl: {severity: [], 'service': svc_name, 'external': external}}
            elif webappurl not in res[protocol][port]:
                res[protocol][port][webappurl] = {severity: [], 'service': svc_name, 'external': external}

            if severity not in res[protocol][port][webappurl]:
                res[protocol][port][webappurl].setdefault(severity, [])

            if not res[protocol][port][webappurl]['service']:
                res[protocol][port][webappurl]['service'] = svc_name

            res[protocol][port][webappurl][severity].append(vuln)
        else:
            logger.debug('Plugin processing: parsing info: ' + plugin)
            if plugin in ['Nessus SYN scanner', 'Nessus SNMP Scanner', 'Nessus TCP scanner', 'Nessus UDP Scanner']:
                protocol = ri.get('protocol')
                port = ri.get('port')
                svc_name = ri.get('svc_name')
                if svc_name == 'general' and port == '0':
                    continue
                else:
                    if protocol not in res:
                        res.setdefault(protocol, {port: {webappurl: {severity: [], 'service': svc_name, 'external': external}}})
                    elif port not in res[protocol]:
                        res[protocol].setdefault(port, {webappurl: {severity: [], 'service': svc_name, 'external': external}})
                    elif webappurl not in res[protocol][port]:
                        res[protocol][port].setdefault(webappurl, {severity: [], 'service': svc_name, 'external': external})
                    else:
                        res[protocol][port][webappurl]['service'] = svc_name

            else:
                info = process_info(ri)
                # returns {'protocol': protocol, 'port': port, 'service': {key: info}}
                #      or {'host': {key: value}}  
                #      or None
                if not info:
                    continue

                if 'host' in info:
                    logger.info('processing host info ' + repr(info['host']))
                    for key in info['host']:
                        # res.setdefault(key, info['host'][key])
                        if key in res and res[key]:
                            res[key] += '|' + info['host'][key]
                        else:
                            res[key] = info['host'][key]

                if 'service' in info:
                    port = info['port']
                    protocol = info['protocol']
                    # add dict keys as needed
                    if protocol not in res:
                        res.setdefault(protocol, {port: {webappurl: {severity: [], 'service': None, 'external': external}}})
                    elif port not in res[protocol]:
                        res[protocol].setdefault(port, {webappurl: {severity: [], 'service': None, 'external': external}})
                    elif webappurl not in res[protocol][port]:
                        res[protocol][port].setdefault(webappurl, {severity: [], 'service': None, 'external': external})

                    for key in info['service']:
                        if key == 'errors':
                            # there can be more than one nessus errors per service
                            res[protocol][port][webappurl].setdefault(key, []).append(info['service'][key])
                        else:
                            logger.debug('adding service info to result: ' + key + ', ' + repr(info['service'][key]))
                            if key in res[protocol][port][webappurl] and res[protocol][port][webappurl][key]:
                                if plugin != 'HTTP Server Type and Version':
                                    res[protocol][port][webappurl][key] = info['service'][key]
                                else:
                                    logger.debug('ignoring HTTP Server Type and Version output to avoid clobbering existing data')
                            else:
                                res[protocol][port][webappurl][key] = info['service'][key]


    return res

def process_scan_policy(scan_policy):
#NOTE: more detailed parsing of ports can be done, needs investigation of benefits
# only worth it if more than just the most common UDP services are scanned as Nessus seems to pick them up regardless of port scan settings
#                   'network_scanners.syn': None,
#                   'network_scanners.tcp': None,
#                   'network_scanners.udp': None,
    interesting = {'unscanned_closed': 'unscanned_closed',
                   'reduce_connections_on_congestion': 'throttle_on_congestion',
                   'port_range': 'tcp_port_range',
                   'TARGET': 'target' }
    result = {}
#    udp_ports = ''
#    all_ports = ''
#    tcp_ports = ''
    try:
        policy_name = scan_policy.find('policyName').text.strip()
    except:
        logger.warn('no policy name found')
        policy_name = ''

    result.setdefault('policy', policy_name)

    for pref in scan_policy.find('Preferences').find('ServerPreferences').findall('preference'):
        pref_name = pref.find('name').text.strip()
        if pref_name in interesting:
            value = pref.find('value').text.strip()
#            if pref_name == 'port_range':
#                udp_ports = re.findall('U:([0-9,-]+)', value)[0]
#                all_ports = re.findall('^([0-9,-]+),[UT]:', value)[0]
#                tcp_ports = re.findall('T:([0-9,-]+)', value)[0]
#            elif interesting[pref_name]:
            value = 'false' if value == 'no' else value
            value = 'true' if value == 'yes' else value
            table_field = interesting[pref_name]
            result.setdefault(table_field, value)
            #logger.debug('#### ' + table_field + '/' + value)
#            elif pref_name == 'network_scanners.syn' and value == 'yes':
#            elif pref_name == 'network_scanners.udp' and value == 'yes':
        #else:
        #    logger.debug('####ignoring preference: ' + pref_name)

    return result

def parse_file(filename, eng_type):
    status = {'error': False}
    #plugin_set = set()
    res = []
    with open(filename, 'r') as xmldata:
        logger.debug('opened ' + filename + ', parsing')
        try:
            tree = ElementTree.parse(filename)
        except ElementTree.ParseError as e:
            status['error'] = 'Invalid XML: ' + repr(e)
            logerror(__name__, getframeinfo(currentframe()).lineno, status['error'])
            return status, None, None
        except Exception as e:
            status['error'] = repr(e)
            logerror(__name__, getframeinfo(currentframe()).lineno, status['error'])
            return status, None, None

        logger.debug('XML is valid, loaded ok')
        root = tree.getroot()
        scan_preferences = process_scan_policy(root.find('Policy'))
        # audit scans other than a credentialed patch audit can only be imported into an audit engagement
        if (scan_preferences['policy'] != 'Credentialed Patch Audit' and re.search('Audit', scan_preferences['policy']))\
                                                    and eng_type != 'audit':

            logger.warning('cant import audit scan into a ' + eng_type + ' engagement')
            status['error'] = 'Audit scans can only be imported into an audit engagement'
            return status, None, None
        elif not (scan_preferences['policy'] != 'Credentialed Patch Audit' and re.search('Audit', scan_preferences['policy']))\
                                                    and eng_type == 'audit':
            logger.warning('cant import audit scan into a ' + eng_type + ' engagement')
            status['error'] = 'Audit engagements can only import audit scans'
            return status, None, None

        for host in root.find('Report').findall('ReportHost'):
            if eng_type == 'audit':
                host_data = process_csa(host)
            else:
                host_data = process_host(host)

            if host_data:
                res.append(host_data)
                #plugin_set = plugin_set | host_data['plugin_set']
            else:
                logger.info('empty dataset for host, ignoring')

    #logger.info('plugin_set size: ' + str(len(plugin_set)))
    #for p in plugin_set:
    #    logger.info(p)

    return (status, res, scan_preferences)

def store_nessus_scans(parsed_data, scan_preferences, conn, curs):
    # parsed_data not used here, working with scan_preferences
    logger.info('storing nessus scan preferences data')
    fields = get_table_fields('nessus_scans')
    values = []
    for field in fields:
        if field == 'engagement_id':
            value = eid
        elif field == 'filename':
            value = scan_filename
        elif field == 'scan_type':
            value = scan_type
        elif field in scan_preferences:
            value = scan_preferences[field]
        else:
            logger.debug('no value found for field ' + field)
            value = None

        values.append(value)

    placeholders = '%s,'*(len(fields) - 1) + '%s'
    try:
        curs.execute('insert into nessus_scans (' + ','.join(fields) + ') values (' + placeholders + ')\
                               returning id', tuple(values))
        global nessus_id
        nessus_id = curs.fetchone()[0]
    except conn.Error as e:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to store nessus scan, database error')
        logger.error(e.pgerror)
        conn.close()
        return False
    else:
        global scan_uri
        scan_uri = 'nessus/' + str(nessus_id)

    logger.info('done storing nessus scan preferences data (' + str(nessus_id) + ')')

    return True

def store_issue_seen(issue, fingerprint, curs, _issue_id=None):
    title = issue['title']
    fields = get_table_fields('issues_seen')
    # if issue not previously seen or has been updated, store it
    # title, description, remediation, scanner and fingerprint cannot be null
    cols = ['scanner', 'fingerprint']
    vals = ['nessus', fingerprint]
    for fld in fields:
        if fld in cols:
            continue
        elif fld in issue and issue[fld] is not None:
            cols.append(fld)
            vals.append(issue[fld])
        else:
            logger.debug('no data for field ' + fld)

    if _issue_id:
        sql = get_pg_update_sql('issues_seen', cols, 'where id = %s')
        vals.append(_issue_id)
        curs.execute(sql, tuple(vals))
        logger.info('nessus issue updated: ' + title)
        issue_seen_id = _issue_id
    else:
        placeholders = '%s,'*(len(cols) - 1) + '%s'
        sql = 'insert into issues_seen (' + ','.join(cols) + ') values (' + placeholders + ') returning id'
        curs.execute(sql, tuple(vals))
        issue_seen_id = curs.fetchone()[0]
        logger.info('new nessus issue stored: ' + title)

    return issue_seen_id

def store_findings(parsed_data, scan_preferences, conn, curs):
    '''store findings from standard (not audit) scans
       adds data to findings and issues_seen tables'''

    logger.info('storing findings data')

    # compile nessus issues_seen
    qry = db_getdict("select id, title, severity, plugin_id, fingerprint from issues_seen where scanner = 'nessus'")
    if qry['success']:
        issues_seen = {x.pop('title'): x for x in qry['data']}
    else:
        issues_seen = {}
        logger.error('query failed')

    # compile existing findings
    dcurs = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    dcurs.execute('select coalesce(ipv4, ipv6) as ip, protocol, port, vhost, findings.id, title,\
                          findings.external, findings.scan_uri_list\
                   from findings\
                     join issues_seen on issue_id = issues_seen.id\
                     join services on findings.service_id = services.id\
                     join hosts on services.host_id = hosts.id\
                   where findings.engagement_id = %s', (eid,))
    data = dcurs.fetchall()
    dcurs.close()

    #TODO check if compiling service data and using vuln svc_name to update service value in services table will add info

    stored_findings = {}
    if data:
        for sf in data:
            key = ''.join([sf['ip'], sf['protocol'], str(sf['port']), str(sf['vhost'])])
            # there can be multiple findings of a given severity against a service on a host
            # but they will all have unique titles
            if key in stored_findings:
                stored_findings[key][sf['title']] = {'id': sf['id'], 'external': sf['external'], 'scan_uri_list': sf['scan_uri_list']}
            else:
                stored_findings[key] = {sf['title']: {'id': sf['id'], 'external': sf['external'], 'scan_uri_list': sf['scan_uri_list']}}

    logger.info('compiled existing data, entering store loop')
    fields = get_table_fields('findings')
    issue_fingerprints = {}
    # loop through hosts and store unseen issues and findings
    for host in parsed_data:
        ip = host['ipv4'] if 'ipv4' in host else host['ipv6']

        for key in host.keys():
            if type(host[key]) is not dict:
                continue
            else:
                protocol = key
                logger.debug('protocol is ' + protocol)
            for port in host[protocol]:
                logger.debug('port is ' + str(port))
                for webappurl in host[protocol][port]:
                    for severity in host[protocol][port][webappurl]:
                        # issues of all severities go into the findings table
                        if severity in ['0', '1', '2', '3', '4']:
                            for issue in host[protocol][port][webappurl][severity]:
                                title = issue['title']
                                # check for duplicate findings
                                fkey = ''.join([ip, protocol, str(port), str(webappurl)])
                                # if there is a finding against this service and it matches the current one
                                # e.g. if importing external and internal scans against same IP space
                                if fkey in stored_findings and issue['title'] in stored_findings[fkey]:
                                    scan_uri_list = stored_findings[fkey][title]['scan_uri_list'] + ',' + scan_uri
                                    if scan_type == 'external' and not stored_findings[fkey][title]['external']:
                                        # if this scan is external, update exposure for the finding and the service
                                        logger.debug('updating duplicate finding, setting as visible externally: ' + fkey + '/' + title)
                                        curs.execute("update findings set scan_uri_list = %s, external = true where id = %s",
                                                (scan_uri_list, stored_findings[fkey][title]['id']))
                                        #NOTE this should already be updated when storing services
                                        # if actually needed, should also deal with scan_uri_list
                                        #curs.execute('update services set external = %s \
                                        #    where id = (select service_id from findings where id = %s)',
                                        #        (True, stored_findings[fkey][title]['id']))
                                    else:
                                        logger.debug('stored finding is external: ' + str(stored_findings[fkey][title]['external']))
                                        logger.debug('adding scan_uri to existing finding: ' + fkey + '/' + title + '/' + str(external))
                                        curs.execute("update findings set scan_uri_list = %s where id = %s",
                                                (scan_uri_list, stored_findings[fkey][title]['id']))
                                else:
                                    # this is a new finding
                                    # severity is in the data structure outside the issue itself, add it so it can be stored
                                    issue['severity'] = severity
                                    issue['remediation'] = issue.pop('solution') if issue['solution'] else 'n/a'
                                    fingerprint = issue_fingerprints[title] if title in issue_fingerprints else get_fingerprint(issue)
                                    if title in issues_seen:
                                        if issues_seen[title]['plugin_id'] != issue['plugin_id']:
                                            logger.debug('analysing results from different plugins with same title')
                                            if int(issues_seen[title]['severity']) >= int(severity):
                                                logger.info('same title issue at same or lower severity, ignoring: ' + title)
                                                #TODO there may be room for improvement here
                                                # track the nessus assigned severity as well (in addition to our cvss-based)
                                                # and clobber with the higher one
                                                # may be possible to merge too, without messing up library scanner text change tracking
                                                continue
                                            else:
                                                logger.info('same title issue at higher severity, updating: ' + title)
                                                logger.info('current severity: ' + str(severity) + ', seen severity: ' + str(issues_seen[title]['severity']))
                                                # update the stored info in database so the texts match the higher severity issue
                                                _issue_id = issues_seen[title]['id']
                                                issue_seen_id = store_issue_seen(issue, fingerprint, curs, _issue_id=_issue_id)
                                                # update the fingerprint in the map for the current import
                                                issue_fingerprints[title] = get_fingerprint(issue)
                                                # update the stored issues_seen dict
                                                issues_seen[title] = {'id': issue_seen_id,
                                                                    'fingerprint': issue_fingerprints[title],
                                                                    'severity': severity,
                                                                    'plugin_id': issue['plugin_id']}

                                        # issues_seen holds all nessus issues seen in database, across engagements and customers
                                        elif issues_seen[title]['fingerprint'] == fingerprint:
                                            logger.debug('issue already seen and is not updated')
                                            issue_seen_id = issues_seen[title]['id']
                                        else:
                                            logging.debug('updating issue details: ' + title)
                                            _issue_id = issues_seen[title]['id']
                                            issue_seen_id = store_issue_seen(issue, fingerprint, curs, _issue_id=_issue_id)
                                            issues_seen[title]['fingerprint'] = fingerprint
                                    else:
                                        issue_seen_id = store_issue_seen(issue, fingerprint, curs)
                                        # update the existing issues record so we don't try to store this issue again
                                        issues_seen[title] = {'id': issue_seen_id,
                                                            'fingerprint': fingerprint,
                                                            'severity': severity,
                                                            'plugin_id': issue['plugin_id']}

                                    # issue is in issues seen now, store finding
                                    cols = ['engagement_id', 'issue_id', 'external', 'vhost', 'scan_uri_list']
                                    vals = [eid, issue_seen_id, external, webappurl, scan_uri]
                                    for field in fields:
                                        if field in cols:
                                            continue
                                        elif field == 'service_id':
                                            if ip+protocol+str(port)+str(webappurl) in service_map:
                                                value = service_map[ip+protocol+str(port)+str(webappurl)]
                                            else:
                                                logerror(__name__, getframeinfo(currentframe()).lineno, 'service key missing')
                                                logger.error(ip+protocol+str(port)+str(webappurl))
                                                logger.error(repr(service_map))
                                                conn.rollback()
                                                curs.close()
                                                return False
                                        else:
                                            if field in ['cvss', 'cvss3']:
                                                field = 'cvss_base_score' if field == 'cvss' else 'cvss3_base_score'

                                            value = issue[field] if field in issue else None

                                        cols.append(field)
                                        vals.append(value)

                                    placeholders = '%s,'*(len(cols) - 1) + '%s'
                                    logger.debug('storing new finding: ' + fkey + '/' + title + '/' + str(external))
                                    try:
                                        curs.execute('insert into findings (' + ','.join(cols) + ') values (' + placeholders + ')',
                                                        tuple(vals))
                                    except conn.Error as e:
                                        logerror(__name__, getframeinfo(currentframe()).lineno,
                                                 'failed to store findings, database error')
                                        logger.error(e.pgerror)
                                        conn.close()
                                        return False
                        else:
                            logging.debug('bad severity: ' + str(severity))

    logger.info('stored issues and findings')
    return True

def store_csa_findings(parsed_data, scan_preferences, conn, curs):
    logger.info('storing findings data for eid ' + str(eid))
    fields = get_table_fields('csa_findings')
    placeholders = '%s,'*(len(fields) - 1) + '%s'
    qry = db_getdict('select id, title, benchmark, service_name, compliance from csa_findings\
                      where engagement_id = %s', (eid,))
    if qry['success']:
        data = qry['data']
    else:
        data = {}
        logger.error('query failed')

    stored_findings = {}
    if data:
        for _issue in data:
            _benchmark = _issue.pop('benchmark')
            _title = _issue.pop('title')
            _service = _issue.pop('service_name')
            if _service in stored_findings:
                if _benchmark in stored_findings:
                    # issue titles assumed unique within results for a benchmark, within an engagement
                    stored_findings[_service][_benchmark].setdefault(_title, _issue)
                else:
                    stored_findings[_service].setdefault(_benchmark, {_title: _issue})
            else:
                stored_findings.setdefault(_service, {_benchmark: {_title: _issue}})
        
    else:
        logger.debug('no stored csa findings')

    for host in parsed_data:
        #res['tcp']['0'][result].append(csa_issue)
        # check for duplicate finding
        _service_name = host['service_name']
        for csa_compliance in host['tcp']['0']:
            for csa_issue in host['tcp']['0'][csa_compliance]:
                #logger.debug('storing csa issue ' + csa_issue['title'])
                _benchmark = csa_issue['benchmark']
                # if issues from the same benchmark are already stored under this engagement
                # merge the current import, overwriting any duplicates
                if _service_name in stored_findings and _benchmark in stored_findings[_service_name]:
                    #NOTE: may need to check audit level per issue, for now assuming benchmark name is enough
                    _title = csa_issue['title']
                    if _title in stored_findings[_service_name][_benchmark]:
                        stored_compliance = stored_findings[_service_name][_benchmark][_title]['compliance']
                        if csa_issue['compliance'] != stored_compliance:
                            # assume a later import is more current and clobber any duplicate results
                            logger.debug('overwriting: ' + _title + ' with results from current import')
                            curs.execute('update csa_findings set (description, rationale, impact, solution, plugin_output,\
                                                 compliance, reference, nessus_id) = (%s, %s, %s, %s,%s, %s,%s, %s) where id = %s',
                                                 (csa_issue['description'], csa_issue['rationale'], csa_issue['impact'],
                                                  csa_issue['solution'], csa_issue['plugin_output'], csa_issue['compliance'],
                                                  csa_issue['reference'], nessus_id, stored_findings[_benchmark][_title]['id']))

                        else:
                            logger.debug('ignoring duplicate: ' + _title)

                else:
                    ip = host['ipv4']
                    for item in csa_issue:
                        if item not in fields:
                            logger.warn(item + ' in issue is not being stored in db, no corresponding column')

                        values = []
                        # csa_issue = {'check_name': check_name, 'benchmark': benchmark, 'result': result,\
                        # 'description': description, 'rationale': rationale, 'impact': impact,\
                        # 'solution': solution, 'audit_level': audit_level, 'control_set': control_set}
                        for field in fields:
                            if field == 'engagement_id':
                                value = eid
                            elif field == 'nessus_id':
                                value = nessus_id
                            elif field == 'service_name':
                                value = _service_name
                            elif field == 'service_id':
                                if ip + 'tcp0' in service_map:
                                    value = service_map[ip + 'tcp0']
                                else:
                                    logerror(__name__, getframeinfo(currentframe()).lineno, 'service key missing')
                                    logger.error(ip + 'tcp0')
                                    logger.error(repr(service_map))
                                    conn.rollback()
                                    curs.close()
                                    return False
                            else:
                                value = csa_issue[field] if field in csa_issue else None

                            values.append(value)

                    try:
                        #print('fields: ' + str(len(fields)))
                        #print('values: ' + str(len(values)))
                        #print(repr(fields))
                        #print(repr(values))
                        curs.execute('insert into csa_findings (' + ','.join(fields) + ') values (' + placeholders + ')', tuple(values))
                    except conn.Error as e:
                        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to store findings, database error')
                        logger.error(e.pgerror)
                        conn.close()
                        return False

    logger.info('stored csa_findings')
    return True

def update_host(fields, parsed, stored, conn, curs):
    logger.info('updating host')
    update_cols = []
    update_vals = []
    for field in fields:
        # if host visible both internally and externally, store the id of the external scan
        # assumption is that anything visible externally will be visible internally too
        # hosts/services with an internal scan id are only visible internally
        # dont overwrite any external id with an internal one
        if field == 'nessus_id' and scan_type == 'internal':
            continue
        # second scan clobbers any values present from first scan - it could merge instead
        elif field in parsed and parsed[field]:
            if field not in stored or parsed[field] != stored[field]:
                oldval = 'undef' if field not in stored else str(stored[field])

                logger.debug('updating field from ' + oldval + ' to ' + str(parsed[field]))
                update_cols.append(field)
                update_vals.append(parsed[field])
            else:
                logger.debug('parsed and stored data identical, ignoring: ' + field)
        else:
            logger.debug('no parsed data for ' + field + ' during host update')

    if update_cols:
        sql = 'update hosts set (' + ', '.join(update_cols) + ') = (' + '%s, '*(len(update_vals) - 1) + '%s) where id = %s'\
            if len(update_cols) > 1 else\
            'update hosts set ' + update_cols[0] + ' = %s where id = %s'

        update_vals.append(stored['id'])
        logger.debug('update sql: ' + sql)
        logger.debug('update values: ' + repr(update_vals))
        try:
            curs.execute(sql, tuple(update_vals))
        except conn.Error as e:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to update host, database error')
            logger.error(e.pgerror)
            conn.close()
            return False

        logger.info('updated host columns: ' + repr(update_cols))
    else:
        logger.info('parsed host data identical to stored, nothing to update')

    return True

def store_hosts(parsed_data, scan_preferences, conn, curs):
    logger.info('storing hosts data')
    fields = get_table_fields('hosts')
    if fields:
        placeholders = '%s,'*(len(fields) - 1) + '%s'
    else:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to get host table fields, trying again')
        time.sleep(1)
        fields = get_table_fields('hosts')
        placeholders = '%s,'*(len(fields) - 1) + '%s'

    #NOTE potential efficiency savings here if only the relevant subset of scan_data is passed
    logger.debug('getting stored hosts for eid ' + str(eid))
    qry = db_getdict('select id, ipv4, ipv6, fqdn, os, rdns from hosts where engagement_id = %s', (eid,))
    if qry['success']:
        stored_data = qry['data']
    else:
        stored_data = {}
        logger.error('query failed')
    # dictify hosts by ipv4 if present, else by ipv6
    stored_hosts = {}
    unknown_ip_hosts = {}
    if stored_data:
        logger.debug('loaded stored data: ' + str(len(stored_data)) + ' hosts')
        for host in stored_data:
            if host['ipv4']:
                if host['ipv4'].startswith('0.0.0.'):
                    logger.debug('adding unknown IP host: eid/ip - ' + str(eid) + '/' + host['ipv4'])
                    unknown_ip_hosts[host['fqdn'].lower()] = host
                else:
                    logger.debug('adding existing host: eid/ip - ' + str(eid) + '/' + host['ipv4'])
                    stored_hosts[host['ipv4']] = host
                    host_map[host['ipv4']] = host['id']
            elif host['ipv6']:
                logger.debug('adding existing host: eid/ip - ' + str(eid) + '/' + host['ipv6'])
                stored_hosts[host['ipv6']] = host
                host_map[host['ipv6']] = host['id']
            else:
                logerror(__name__, getframeinfo(currentframe()).lineno, 'existing host in db has no ip address, ignoring')
                logger.error(repr(host))

    for host in parsed_data:
        if 'ipv4' in host and host['ipv4'] in stored_hosts:
            logger.debug('updating host ' + host['ipv4'])
            if not update_host(fields, host, stored_hosts[host['ipv4']], conn, curs):
                return False
        elif 'ipv6' in host and host['ipv6'] in stored_hosts:
            logger.debug('updating host ' + host['ipv6'])
            if not update_host(fields, host, stored_hosts[host['ipv6']], conn, curs):
                return False
        else:
            ip = host['ipv4'] if 'ipv4' in host else host['ipv6']
            for hostname in host['vhost_list']:
                hostname = hostname.lower()
                if hostname in unknown_ip_hosts:
                    logger.debug('parsed data provides real ip for ' + hostname)
                    if update_host(fields, host, unknown_ip_hosts[hostname], conn, curs):
                        # hosts stored in unknown_ip_hosts dont have a hostmap entry yet
                        host_map[ip] = unknown_ip_hosts[hostname]['id']
                        break
                    else:
                        return False

            if ip in host_map:
                logger.debug('using existing host entry with updated IP: ' + ip)
                continue

            values = []
            for field in fields:
                if field == 'engagement_id':
                    value = eid
                elif field == 'os':
                    if 'os_detail' in host:
                        guesslist = re.sub(r'[\n\r]', '|', host['os_detail']).split('|')
                        if len(guesslist) > 1:
                            shortened = get_longest_match(guesslist)
                            value = shortened if shortened else '|'.join(guesslist)
                        else:
                            value = guesslist[0]
                    else:
                        value = None

                    if 'os' in host:
                        if not host['os']:
                            values.append(value)
                            continue

                        os_value = host['os'].strip()
                        if value:
                            for os_value in host['os'].strip().split('|'):
                                # value has been derived from os_detail above
                                if not re.search(os_value, value, re.IGNORECASE):
                                    # os provides new info, append it
                                    value += '|' + os_value
                                    logger.debug(field + ' append os ' + os_value + ', now ' + value)
                                else:
                                    logger.debug(field + ' value already exists: ' + repr(host['os']) + repr(host['os_detail']))
                        elif os_value:
                            logger.debug('add os ' + os_value)
                            value = os_value
                        #else:
                            #logger.debug('no os value: ' + repr(host))
                    else:
                        value = None
                elif field == 'fqdn':
                    value = host[field] if field in host else None
                    if 'bad_fqdn' in host and host['bad_fqdn'] == value:
                        value = None
                    logger.debug('added fqdn ' + str(value))
                else:
                    value = host[field] if field in host else None
                    logger.debug('added ' + field + ' ' + str(value))

                values.append(value)

            try:
                curs.execute('insert into hosts (' + ','.join(fields) + ') values (' + placeholders + ')\
                                       returning id', tuple(values))
                hid = str(curs.fetchone()[0])
            except conn.Error as e:
                logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to store host data, database error')
                logger.error(e.pgerror)
                conn.close()
                return False

            host.setdefault('id', hid)
            if 'ipv4' in host:
                host_map.setdefault(host['ipv4'], hid)
                stored_hosts.setdefault(host['ipv4'], host)
                logger.debug('adding map entry for host ' + str(hid) + ' -> ' + host['ipv4'])
            else:
                host_map.setdefault(host['ipv6'], hid)
                stored_hosts.setdefault(host['ipv6'], host)
                logger.debug('adding map entry for host ' + str(hid) + ' -> ' + host['ipv6'])

    logger.info('stored hosts data')
    #with open('host_data.txt', 'w+') as f:
    #    for line in copy_data:
    #        f.write(line + '\n')

    return True

def store_nessus_errors (parsed_data, scan_preferences, conn, curs):
    # if service already present it is not an issue here as the new error will just be appended
    # duplicates should not be a problem if created
    logger.info('storing nessus errors')
    fields = get_table_fields('nessus_errors')
    placeholders = '%s,'*(len(fields) - 1) + '%s'
    for host in parsed_data:
        ip = host['ipv4'] if 'ipv4' in host else host['ipv6']
        #NOTE this could also be done by checking key names against set of proto names?
        # if data structure is changed will hide most results so should be noticeable enough :D
        for key in host:
            if type(host[key]) is not dict:
                continue
            else:
                protocol = key
            for port in host[protocol]:
                for webappurl in host[protocol][port]:
                    service_key = ip + protocol + str(port) + str(webappurl)
                    if service_key in service_map:
                        service_id = service_map[service_key]
                    else:
                        # one way this happens is when pre-existing hosts/services are not added to map
                        logerror(__name__, getframeinfo(currentframe()).lineno, 'key not in map')
                        logger.error(service_key + ' not in service_map, skipping nessus error')
                        continue

                    if 'errors' in host[protocol][port][webappurl]:
                        for error in host[protocol][port][webappurl]['errors']:
                            values = [str(service_id), error]

                            try:
                                curs.execute('insert into nessus_errors (' + ','.join(fields) + ') values (' + placeholders + ')',
                                tuple(values))
                            except conn.Error as e:
                                logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to store nessus_errors, database error')
                                logger.error(e.pgerror)
                                conn.close()
                                return False

    logger.info('stored nessus errors')

    return True

def update_service(tbl_fields, parsed, stored, conn, curs):
    logger.info('updating service')
    update_cols = []
    update_vals = []

    # if service visible both internally and externally, store it as external
    # assumption is that anything visible externally will be visible internally too
    external = True if scan_type == 'external' else False
    fields = copy.copy(tbl_fields)
    fields.remove('external')
    if external and not stored['external']:
        logger.debug('updating service to external: ' + repr(stored))
        update_cols.append('external')
        update_vals.append(True)

    if 'scan_uri_list' in stored and stored['scan_uri_list']:
        fields.remove('scan_uri_list')
        scan_uri_set = set(stored['scan_uri_list'].split(','))
        if not scan_uri in scan_uri_set:
            scan_uri_set.add(scan_uri)
            update_cols.append('scan_uri_list')
            update_vals.append(','.join(scan_uri_set))
    else:
        update_cols.append('scan_uri_list')
        update_vals.append(scan_uri)

    for field in fields:
        #TODO second scan clobbers any values present from first scan - it could merge instead
        if field in parsed and parsed[field]:
            if field not in stored or parsed[field] != stored[field]:
                #logger.debug('updating field from ' + str(stored[field]) + ' to ' + str(parsed[field]))
                update_cols.append(field)
                update_vals.append(parsed[field])
            else:
                logger.debug('parsed and stored data identical, ignoring: ' + field)
        else:
            logger.debug('no parsed data for ' + field + ' during service update')

    if update_cols:
        if 'id' not in stored:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'no id in stored')
            logger.error(repr(stored.keys()))

        sql = 'update services set (' + ', '.join(update_cols) + ') = (' + '%s, '*(len(update_vals) - 1) + '%s) where id = %s'\
            if len(update_cols) > 1 else\
            'update services set ' + update_cols[0] + ' = %s where id = %s'

        update_vals.append(stored['id'])
        logger.debug('update sql: ' + sql)
        logger.debug('update values: ' + repr(update_vals))
        try:
            curs.execute(sql, tuple(update_vals))
        except conn.Error as e:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to update service, database error')
            logger.error(e.pgerror)
            conn.close()
            return False

        logger.debug('updated service columns: ' + repr(update_cols))
    else:
        logger.debug('parsed service data identical to stored, nothing to update')

    logger.info('updated service')
    return True

def store_services(parsed_data, scan_preferences, conn, curs):
    logger.debug('storing service')
    dcurs = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    dcurs.execute('select ipv4, ipv6, services.id, protocol, port, service, software, cert_cn, sitemap, web_dir_enum,\
                          no404sent, cgi_enum, robots_txt, injectable_param, php_version, phpmyadmin,\
                          drupal_detected, wordpress_detected, python_detected, dotnet_handlers, embedded_server,\
                          software_favicon, sensitive_param, external, scan_uri_list, webappurl\
                   from hosts left join services on hosts.id = services.host_id\
                   where host_id in (select id from hosts where engagement_id = %s)', (eid,))
    stored_data = dcurs.fetchall()
    dcurs.close()

    stored_services = {}
    # dictify services to ipprotoport -> info format
    if stored_data:
        for s in stored_data:
            if 'id' in s:
                ip = s['ipv4'] if s['ipv4'] else s['ipv6']
                service_key = ip + s['protocol'] + str(s['port']) + str(s['webappurl'])
                stored_services.setdefault(service_key, s)
                #logger.debug('loaded stored service as: ' + repr(stored_services[service_key].keys()))
                service_map.setdefault(service_key, s['id'])
                #logger.debug('existing service mapping: ' + service_key + ' -> ' + str(s['id']))
            else:
                logger.debug('no stored services for host; ' + repr(s))
    else:
        logger.debug('no stored data for this engagement yet')

    logger.debug('stored services: ' + repr(stored_services))

    fields = get_table_fields('services')
    logger.debug(fields)
    for host in parsed_data:
        ip = host['ipv4'] if 'ipv4' in host else host['ipv6']
        #NOTE this could also be done by checking key names against set of proto names?
        # if data structure is changed will hide most results so should be noticeable enough :D
        for key in host:
            if type(host[key]) is not dict:
                continue
            elif ip not in host_map:
                logerror(__name__, getframeinfo(currentframe()).lineno, 'host missing in map')
                logger.error(ip)
                logger.error('host map: ' + repr(host_map))
                continue
            else:
                protocol = key
                #logger.debug('protocol is ' + protocol)

            for port in host[protocol]:
                #logger.debug('port is ' + port)
                for webappurl in host[protocol][port]:
                    # check if anything stored for this service key
                    service_key = ip + protocol + str(port) + str(webappurl)
                    if service_key in stored_services:
                        logger.debug('updating service ' + service_key + ' ' + repr(stored_services[service_key]['external']))
                        if not update_service(fields, host[protocol][port][webappurl], stored_services[service_key], conn, curs):
                            return False
                    else:
                        logger.debug('storing service ' + service_key)
                        values = []
                        # for every service on the host, fill in all fields of the services table
                        #logger.debug(len(fields))
                        for i, field in enumerate(fields):
                            #logger.debug('checking field ' + str(i) + ': ' + field)
                            if field == 'host_id':
                                value = host_map[ip]
                            elif field == 'external':
                                value = external
                            elif field == 'protocol':
                                value = protocol
                            elif field == 'port':
                                value = port
                            elif field == 'scan_uri_list':
                                value = scan_uri
                            elif field == 'webappurl':
                                value = webappurl if webappurl != 'None' else None
                            else:
                                if field in host[protocol][port][webappurl]:
                                    value = host[protocol][port][webappurl][field]
                                else:
                                    value = None

                            values.append(value)
                            logger.debug('field: ' + field + ', value: ' + str(value))

                        placeholders = '%s,'*(len(fields) - 1) + '%s'
                        try:
                            curs.execute('insert into services (' + ','.join(fields) + ') values (' + placeholders + ')\
                                                returning id', tuple(values))
                            maxid = str(curs.fetchone()[0])
                        except conn.Error as e:
                            logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to store service, database error')
                            logger.error(e.pgerror)
                            logger.error(repr(fields))
                            logger.error(repr(values))
                            conn.close()
                            return False

                        # map service identifying parameters to the issue id in findings table
                        service_key = ip+protocol+str(port)+str(webappurl)
                        #NOTE this overlooks http virtual hosts
                        logger.debug('service mapping: ' + service_key + '->' + str(maxid))
                        service_map.setdefault(service_key, maxid)
                        service_data = dict(zip(fields, values))
                        service_data.setdefault('id', maxid)
                        stored_services.setdefault(service_key, service_data)
                        #logger.debug('added ' + service_key + ' to stored services: ' + repr(stored_services[service_key]))

    logger.info('stored services')
    #with open('services_data.txt', 'w+') as f:
    #    for line in copy_data:
    #        f.write(line + '\n')

    return True

def store_virthosts(parsed_data, scan_preferences, conn, curs):
    logger.info('storing virthosts data')
    fields = get_table_fields('http_virthost')
    placeholders = '%s,'*(len(fields) - 1) + '%s'
    dcurs = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    dcurs.execute('select host_id, ipv4, ipv6, fqdn, virthost\
                   from http_virthost join hosts on http_virthost.host_id = hosts.id\
                   where engagement_id = %s', (eid,))
    stored_data = dcurs.fetchall()
    dcurs.close()

    stored = {}
    if stored_data:
        for s in stored_data:
            ip = s['ipv4'] if s['ipv4'] else s['ipv6']
            if ip not in stored:
                stored.setdefault(ip, {'host_id': s['host_id'], 'virthosts': []})

            # this is database data, there should be no duplicates (unique per host)
            stored[ip]['virthosts'].append(s['virthost'])

    for host in parsed_data:
        # if the virthost list is there and not empty
        if 'vhost_list' in host and host['vhost_list']:
            ip = host['ipv4'] if 'ipv4' in host and host['ipv4'] else host['ipv6']
            if ip in stored:
                # virthosts are just inserted, no need for updates
                for virthost in host['vhost_list']:
                    if virthost not in stored[ip]['virthosts']:
                        logger.debug('adding virthost for existing host_id: ' + virthost)
                        values = [str(stored[ip]['host_id']), virthost]
                        try:
                            curs.execute('insert into http_virthost (host_id, virthost) values (%s, %s) on conflict do nothing',
                                           tuple(values))
                            stored[ip]['virthosts'].append(virthost)
                        except conn.Error as e:
                            logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to store virthost, database error')
                            logger.error(e.pgerror)
                            conn.close()
                            return False

            else:
                for virthost in host['vhost_list']:
                    values = [str(host_map[ip]), virthost]
                    try:
                        curs.execute('insert into http_virthost (' + ','.join(fields) + ') values (' + placeholders + ')', tuple(values))
                        logger.debug('stored virthost ' + virthost + ' for ' + ip)
                        stored.setdefault(ip, {'host_id': str(host_map[ip]), 'virthosts': []})
                        stored[ip]['virthosts'].append(virthost)
                    except conn.Error as e:
                        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to store virthost, database error')
                        logger.error(e.pgerror)
                        conn.close()
                        return False

            # check if there is an fqdn value in db and if not update with the first virthost value
            #if not stored[ip]['fqdn']:
            #    try:
            #        curs.execute('update hosts set fqdn = %s where id = %s', (host['virthost'][0], stored[ip]['host_id']))
            #        stored[ip]['fqdn'] = host['virthost'][0]
            #    except conn.Error as err:
            #        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to store virthost, database error: ' + str(err))
            #        conn.close()
            #        return False


    logger.info('stored virthosts')
    return True

def save_db(table, parsed_data, scan_preferences, conn, curs):
    # db_copy(array, table, columns, sep)
    logger.debug('saving data to table ' + table)

    store = {'nessus_scans':  store_nessus_scans,
             'nessus_errors': store_nessus_errors,
             'hosts':         store_hosts,
             'services':      store_services,
             'http_virthost': store_virthosts,
             'findings':      store_findings,
             'csa_findings':  store_csa_findings }

    return store[table](parsed_data, scan_preferences, conn, curs)

# execute as a module
def import_scan(filename, scantype, eng_id, eng_type):
    global scan_type
    scan_type = scantype
    global external
    external = True if scantype == 'external' else False
    global eid
    eid = eng_id
    if not eid:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'no active engagement, aborting import')
        return False

    global unhandled_plugins
    unhandled_plugins = {}
    # a map of issue id to host/protocol/service
    global service_map
    service_map = {}
    # holds the list of columns per table
    global table_fields
    table_fields = {}
    # a map of host IP to ID
    global host_map
    host_map = {}

    # assign the file name to the global variable
    global scan_filename
    scan_filename = filename
    status, data, scan_preferences = parse_file(scan_filename, eng_type)
    if status['error']:
        return status

    #print(repr(data))
    conn = get_db()
    curs = conn.cursor()
    for table in tables:
        # scan_preferences is the bs4 object holding the relevant part of the xml data
        # data is the rest of the bs4 data, parsed 
        if table == 'findings' and eng_type == 'audit':
            saved = save_db('csa_findings', data, scan_preferences, conn, curs)
            # for csa no need to save nessus_errors or virtual hosts
            break
        else:
            saved = save_db(table, data, scan_preferences, conn, curs)

        if not saved:
            status['error'] = 'Failed to save parsed nessus data to database'
            logerror(__name__, getframeinfo(currentframe()).lineno, status['error'])
            if conn:
                conn.close()
            return status

    conn.commit()
    conn.close()

    logger.info('nessus scan imported')
    return status

# execute as standalone
def main():
    filename = sys.argv[1]
    scantype = sys.argv[2]
    eng_id = sys.argv[3]
    eng_type = sys.argv[4]
    import_scan(filename, scantype, eng_id, eng_type)

    # pretty print the data to stdout
    #pp.pprint(data)
    # output a sorted list of plugins which are not currently handled
    #{print(k + ': ' + str(v)) for k, v in sorted(unhandled_plugins.items(), key=lambda item: item[1])}

if __name__ == "__main__":
    main()

