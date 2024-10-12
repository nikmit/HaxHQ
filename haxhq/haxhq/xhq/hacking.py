import logging
import re
import io
import os
import copy
import time
import pylibmc
import ipaddress
from inspect import currentframe, getframeinfo
from collections import OrderedDict, namedtuple
from operator import itemgetter
from itertools import islice
from flask import request, session, g, flash, Flask
from markupsafe import escape
from werkzeug.utils import secure_filename
import xhq.nmap
import xhq.burp
import xhq.nessus
import xhq.amass
import xhq.pingcastle
import xhq.netsparker
import xhq.acunetix
import xhq.qualys
import xhq.zap
import xhq.scnr
from xhq.reporting import summarise_findings, summarise_csa, clear_summary
from xhq.auth import authorise_access
from xhq.util import get_db, db_getrow, db_getcol, db_getdict, db_do, get_engagement_id, get_pg_update_sql, logerror, email_enabled
from xhq.config import severity_map

logger = logging.getLogger(__name__)
logger.setLevel('INFO')
#logger.setLevel('DEBUG')

app = Flask(__name__)
app.config.from_object('def_settings')
supported_scanners = app.config['SUPPORTED_SCANNERS']

def get_vars(prm):
    # get general engagement info
    res = {'page': 'hacking', 'subtitle': 'Hacking', 'view': 'main', 'hidden_fields': ['Import', 'File'], 'user': session['nickname'],
           'isadmin': session['isadmin'], 'user_groups': session['user_groups'], 'internal_scans': [], 'external_scans': [],
           'has_stats': authorise_access('stats'), 'email_enabled': email_enabled()}

    qry = db_getdict('select eid, org_name from engagements where active is true and user_id = %s',
                        (session['user_id'],))
    data = qry['data']
    if data:
        if len(data) > 1:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'multiple engagements marked as activated')
            return { 'error': 'multiple engagements marked as activated' }
        else:
            active_engagement = data[0]

        ae = {}
        for item in ['eid', 'org_name']:
            ae.setdefault(item, active_engagement[item])

        res.setdefault('active_engagement', ae)
        eid = active_engagement['eid']
        # get uploaded files
        imported_files = get_imported_scans(eid)
        if imported_files:
            for entry in imported_files:
                if entry['scan_type'] == 'internal':
                    res['internal_scans'].append(entry)
                else:
                    res['external_scans'].append(entry)
        # get host details
        if 'view' in prm:
            if prm['view'] == 'host':
                res['view'] = 'host'
                res.setdefault('host', get_host_details(prm['hid']))
            else:
                res['view'] = prm['view']
                res = {**res, **get_summary(eid, prm['view'])}
        else:
            logger.warn('no view passed')

    return res

def get_imported_scans(eid):
    sql = "select id::text, substring(filename, 8) as filename, scan_type, '{}' as scanner\
           from {}_scans where engagement_id = %s".format(supported_scanners[0], supported_scanners[0])
    prm = [eid]
    for scanner in supported_scanners[1:]:
        sql += " union all select id::text, substring(filename, 8) as filename, scan_type, '{}' as scanner\
                           from {}_scans where engagement_id = %s".format(scanner, scanner)
        prm.append(eid)

    qry = db_getdict(sql, tuple(prm))
    if qry['success']:
        return qry['data']
    else:
        logger.error('query failed')
        return False


def get_host_details(hid):
    '''get service and vulnerability details for the detailed host view from the hacking page'''
    eid, eng_type = get_engagement_id(test_type=True)
    # check hid belongs to user
    own_hid = db_getcol('select id from hosts where id = %s and engagement_id in (select eid from engagements where user_id = %s)',
                        (hid, session['user_id']))
    if not own_hid:
        logger.warn('refused access to host ' + str(hid) + ' by user ' + session['user_id'])
        flash("Host not found in this user's engagements. If this is a persistent error, please report it.", 'error')
        return None

    qry = db_getrow('select ipv4, ipv6, os, rdns from hosts where id = %s', (hid,) )
    hostdata = qry['data']
    #hostnotes = db_getcol('select note from host_notes where host_id = %s', (hid,) )
    qry = db_getcol('select virthost from http_virthost where host_id = %s', (hid,) )
    virthosts = qry['data']
    if virthosts:
        hostdata.setdefault('hostnames', virthosts)
        qry = db_getdict("select id, coalesce(ipv4, ipv6) as ip from hosts\
                          where id in (select host_id from http_virthost\
                                       where virthost in ('" + "','".join(virthosts) + "'))")
        related = qry['data']
        if related:
            hostdata.setdefault('related', { r['ip']: r['id'] for r in related })

    qry = db_getdict('select service_id, error_text\
                      from nessus_errors\
                      where service_id in (select id from services where host_id = %s)', (hid,))
    errordata = qry['data']

    errors = {}
    if errordata:
        for e in errordata:
            errors.setdefault(e['service_id'], []).append(e['error_text'])

    # check if findings are summarised and autosummarise if appropriate
    summarise = False
    table = 'csa_reporting' if eng_type == 'audit' else 'reporting'
    qry = db_getrow('select summarised, count(id) as num_issues,\
                        count(ready) filter (where ready is true) as ready,\
                        count(merged_with) filter (where merged_with is not null) as merged,\
                        count(deleted) filter (where deleted is true) as deleted\
                       from engagements\
                        left join ' + table + ' on eid = engagement_id\
                       where eid = %s group by summarised', (eid,))
    if qry['success']:
        d = qry['data']
        if d:
            if not d['summarised']:
                if d['num_issues'] == 0 or (d['ready'] == 0 and d['merged'] == 0 and d['deleted'] ==0):
                    summarise = True
        else:
            logger.warn('user trying to access host without an active engagement?')
            return hostdata
    else:
        logger.error('query failed')
        return hostdata

    if not d['summarised']:
        if summarise:
            if d['num_issues']:
                clear_summary()

            if eng_type == 'audit':
                summarise_csa()
            else:
                summarise_findings()
        else:
            logger.debug('reporting table not empty, abandon auto summarising')
            flash('Summary has not been updated after adding or deleting scans. Please drop and summarise from reporting page', 'error')
            return hostdata

    qry = db_getdict('select findings.id, findings.service_id, title, severity, report_vuln_id\
                      from findings join servicevulns on findings.id = servicevulns.finding_id\
                                    join issues_seen on findings.issue_id = issues_seen.id\
                      where findings.service_id in (select id from services where host_id = %s)\
                      order by severity desc', (hid,))
    findingsdata = qry['data']
    findings = {}
    vuln_svcs = set()
    severitymap = {4: 'Crit', 3: 'High', 2: 'Medium', 1: 'Low', 0: 'Info'}
    # compile findings data by severity -> service_id -> [findings]
    if findingsdata:
        for f in findingsdata:
            severity = severitymap[f.pop('severity')]
            sid = f.pop('service_id')
            vuln_svcs.add(sid)
            finding = {key: f[key] for key in f if f[key]}
            finding['severity'] = severity
            if severity in findings:
                if sid in findings[severity]:
                    findings[severity][sid].append(finding)
                else:
                    findings[severity].setdefault(sid, [])
                    findings[severity][sid].append(finding)
            else:
                findings.setdefault(severity, {sid: [finding]})
    else:
        logger.debug('findings query returned no data for host ' + str(hid))

    qry = db_getdict('select id as sid, protocol, port, webappurl, service, software, cert_cn, sitemap, web_dir_enum,\
                             cgi_enum, robots_txt, injectable_param, php_version, phpmyadmin,\
                             drupal_detected as drupal, wordpress_detected as wordpress, python_detected as python,\
                             dotnet_handlers, embedded_server, sensitive_param\
                      from services where host_id = %s order by protocol, port asc', (hid,))
    servicedata = qry['data']
    # compile service data by sid
    services = {}
    if servicedata:
        for s in servicedata:
            sid = s.pop('sid')
            injectable_param = s.pop('injectable_param')
            sensitive_param = s.pop('sensitive_param')
            svc = { key: s[key] for key in s if s[key] }
            if injectable_param:
                svc['injectable_param'] = escape(injectable_param)
            if sensitive_param:
                svc['sensitive_param'] = escape(sensitive_param)
            if 'sitemap' in svc:
                # remove duplicates from sitemaps
                # TODO this would be much more usable with dynamic expansion of paths
                logger.debug('removing duplicates from sitemap, current size: ' + str(len(svc['sitemap'])))
                data = [ s.strip() for s in svc['sitemap'].split(',') ]
                svc['sitemap'] = ', '.join(set(data))
            services[sid] = svc

    # add services with findings to the top of the list in order of severity (as ordered in fingings db query)
    if findings:
        sids_by_severity = []
        hostdata.setdefault('vuln_services', [])
        for severity in findings:
            for sid in findings[severity]:
                services[sid].setdefault('findings', [])
                services[sid]['findings'] += findings[severity][sid]
                if sid in errors:
                    services[sid]['errors'] = errors[sid]
                if sid not in sids_by_severity:
                    sids_by_severity.append(sid)

        for sid in sids_by_severity:
            hostdata['vuln_services'].append(services[sid])
    else:
        logger.debug('no findings for host ' + str(hid))


    # add services without findings
    if servicedata:
        hostdata.setdefault('services', [])
        for sid in services:
            if sid in vuln_svcs:
                continue

            #value = service[item] if isinstance(service[item], bool) else str(service[item])
            if sid in errors:
                services[sid]['errors'] = errors[sid]

            hostdata['services'].append(services[sid])
    else:
        logger.debug('no service data returned for host id' + str(hid))

    #logger.debug(repr(hostdata))
    return hostdata

def get_summary(eid, view):
    # eid already derived from user in get_vars, no further authorisation needed
    result = { 'data':          [],
               'main_colset':   [ 'host', 'port', 'service', 'software', 'findings', 'errors' ],
               'filter':        { 'host': None, 'port': None, 'service': None, 'software': None, 'findings': None} }

    host_id_list = []
    if view == 'filter':
        params = { param:value for (param, value) in request.form.items() if value }
        del params['csrf_token']
        result['filter'] = result['filter'] | params

        if params:
            logger.debug('filtering with ' + repr(params))
            if 'host' in params:
                filtr = params['host']
                logger.debug('filtering by host: ' + filtr)

                #NOTE this doesn't track exposure on any related findings, theoretically that could mishandle virthosts/webfiltering
                if filtr in ['internal', 'external']:
                    isexternal = 'true' if filtr == 'external' else 'false'
                    sql = 'select id::text from hosts where engagement_id = %s\
                                                and id in (select host_id from services where external is ' + isexternal +')'
                    qry = db_getcol(sql, (eid, ))
                    if qry['data']:
                        logger.debug('got ' + str(len(qry['data'])) + ' host ids for host filter ' + filtr)
                        host_id_list = qry['data']

                elif filtr in ['public', 'private']:
                    qry = db_getdict('select id, ipv4 from hosts where engagement_id = %s', (eid,))
                    data = qry['data']
                    private_subnets = [ipaddress.ip_network(n) for n in ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12',
                                                                         '192.168.0.0/16']]
                    for host in data:
                        public = True
                        for subnet in private_subnets:
                            ip = ipaddress.ip_address(host['ipv4'])
                            if ip in subnet:
                                if filtr == 'private':
                                    host_id_list.append(str(host['id']))
                                else:
                                    public = False

                                break

                        #NOTE this ignores multicast etc ranges, that seems acceptable right now
                        if filtr == 'public' and public :
                            host_id_list.append(str(host['id']))

                else:
                    filtr = '%' + filtr + '%'
                    qry = db_getcol('select id::text from hosts where engagement_id = %s\
                                                             and (ipv4::text like %s\
                                                                  or ipv6::text like %s\
                                                                  or lower(os) like lower(%s)\
                                                                  or lower(fqdn) like lower(%s))\
                                     union all select host_id::text from http_virthost\
                                                where host_id in (select id from hosts where engagement_id = %s)\
                                                  and virthost like %s', (eid,filtr,filtr,filtr,filtr,eid,filtr))
                    if qry['success']:
                        if qry['data']:
                            host_id_list = qry['data']
                            logger.debug('got ' + str(len(host_id_list)) + ' host ids for filter ' + filtr)
                                                # if host_id_list is empty at this point, set the search as failed
                    else:
                        logger.error('query failure')

                if not host_id_list:
                    # if the specified host filter yields nothing, applying further filters is pointless
                    return result

            # if host_id_list is empty at this point, there is no host filtering
            # all queries from here on are against the services table
            if 'port' in params:
                filtr = params['port']
                logger.debug('filtering by port: ' + str(filtr))

                if filtr == '*':
                    proto_term = '*'
                    port_term = None
                elif re.search('/', filtr):
                    proto_term, port_term = filtr.split('/')
                elif re.match('^[a-zA-Z]+$', filtr):
                    proto_term = filtr
                    port_term = None
                elif re.match('^\d+$', filtr):
                    proto_term = None
                    port_term = filtr
                else:
                    logger.info('ignoring port search, failed to match term ' + str(filtr))
                    return None

                sql = 'select host_id::text from services where host_id in'
                prm = []

                if host_id_list:
                    logger.debug('existing host id list has ' + str(len(host_id_list)) + ' entries')
                    sql += " ('" + "','".join(host_id_list) + "')"
                else:
                    sql += ' (select id from hosts where engagement_id = %s)'
                    prm.append(eid)

                # get a list of host_id values for merging with any list generated above
                if proto_term:
                    logger.debug('restricting port search to protocol ' + proto_term)
                    sql += ' and lower(protocol) like lower(%s)'
                    prm.append('%' + proto_term + '%')
                if port_term:
                    logger.debug('restricting port search to port ' + port_term)
                    sql += ' and port::text like %s'
                    prm.append('%' + port_term + '%')

                sql += ' group by host_id'
                qry = db_getcol(sql, tuple(prm))
                if qry['success']:
                    if qry['data']:
                        host_id_list = qry['data']
                        logger.debug('got ' + str(len(host_id_list)) + ' host ids for filter ' + filtr)
                                            # if host_id_list is empty at this point, set the search as failed
                else:
                    logger.error('query failure')

            if 'service' in params:
                filtr = params['service']
                logger.debug('filtering by service: ' + filtr)

                sql = 'select host_id::text from services where host_id in'
                prm = []

                if host_id_list:
                    logger.debug('existing host id list has ' + str(len(host_id_list)) + ' entries')
                    sql += " ('" + "','".join(host_id_list) + "')"
                else:
                    sql += ' (select id from hosts where engagement_id = %s)'
                    prm.append(eid)

                # get a list of host_id values for merging with any list generated above
                termlist = filtr.split('|')
                logger.debug('split term with | to ' + repr(termlist))
                sql += ' and ('
                for i, t in enumerate(termlist):
                    sql += ' lower(service) like lower(%s) or' if i < len(termlist) - 1 else ' lower(service) like lower(%s)'
                    prm.append('%' + t + '%')
                sql += ') group by host_id'

                qry = db_getcol(sql, tuple(prm))
                if qry['success']:
                    if qry['data']:
                        host_id_list = qry['data']
                        logger.debug('got ' + str(len(host_id_list)) + ' host ids for filter ' + filtr)
                                            # if host_id_list is empty at this point, set the search as failed
                else:
                    logger.error('query failure')

            if 'software' in params:
                filtr = params['software']
                logger.debug('filtering by software: ' + filtr)

                sql = 'select host_id::text from services join hosts on hosts.id = host_id where'
                prm = []
                if host_id_list:
                    logger.debug('existing host id list has ' + str(len(host_id_list)) + ' entries')
                    sql += " host_id in ('" + "','".join(host_id_list) + "')"
                else:
                    sql += ' engagement_id = %s'
                    prm.append(eid)

                sql += ' and (lower(os) like lower(%s) or\
                          lower(software) like lower(%s) or\
                          lower(software_favicon) like lower(%s) or\
                          lower(phpmyadmin) like lower(%s) or\
                          lower(drupal_detected) like lower(%s) or\
                          lower(wordpress_detected) like lower(%s) or\
                          lower(python_detected) like lower(%s) or\
                          lower(dotnet_handlers) like lower(%s) or\
                          lower(php_version) like lower(%s)'

                prm += ['%' + filtr + '%'] * 9

                try:
                    if re.search(filtr, 'embedded server'):
                        logger.debug('search term applies to embedded server')
                        sql += ' or embedded_server is true) group by host_id'
                    else:
                        sql += ') group by host_id'
                except:
                    logger.debug('search term contains unescaped regex chars, ignoring')
                    sql += ') group by host_id'

                qry = db_getcol(sql, tuple(prm))
                if qry['success']:
                    if qry['data']:
                        host_id_list = qry['data']
                        logger.debug('got ' + str(len(host_id_list)) + ' host ids for filter ' + filtr)
                else:
                    logger.error('query failure')

            if 'findings' in params:
                filtr = params['findings']
                logger.debug('filtering by findings: ' + filtr)

                sql = 'select host_id::text from services where host_id in'
                prm = []

                if host_id_list:
                    logger.debug('existing host id list has ' + str(len(host_id_list)) + ' entries')
                    sql += " ('" + "','".join(host_id_list) + "')"
                else:
                    sql += ' (select id from hosts where engagement_id = %s)'
                    prm.append(eid)

                # try to translate the typed chars to a numeric severity level
                severity = None
                severity_dict = { 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical' }
                for k,v in severity_dict.items():
                    if v.lower().startswith(filtr.lower()):
                        severity = k
                        break

                if severity:
                    logger.debug('getting severity for filter ' + filtr)

                    sql += ' and id in (select service_id from findings join issues_seen on issue_id = issues_seen.id\
                                        where severity = %s)'
                    prm.append(severity)

                else:
                    logger.debug('cant translate findings filter to severity, ignoring: ' + filtr)

                sql += ' group by host_id'
                qry = db_getcol(sql, tuple(prm))
                if qry['success']:
                    host_id_list = qry['data']
                    logger.debug('got ' + str(len(host_id_list)) + ' host ids for filter ' + filtr)
                    if not host_id_list:
                        return result
                else:
                    logger.error('query failed')

            if host_id_list:
                logger.debug('final host id list lenght is ' + str(len(host_id_list)))
                logger.debug('getting details for the hosts that passed the filter/s')
                # get the actual host data using the host_id_list
                hostdata_sql = "select hosts.id as hid, ipv4, ipv6, fqdn, os, host_notes.id as note_id\
                                from hosts\
                                  left join host_notes on host_notes.host_id = hosts.id\
                                where hosts.id in ('" + "','".join(host_id_list) + "')\
                                order by ipv4 asc limit 1000"
                prm = []

            else:
                logger.debug('no host ids for this filter, returning empty dataset')
                return result
        else:
            logger.debug('empty filter used, displaying everything')

    if 'hostdata_sql' not in locals():
        # if hostdata_sql is undefined, the filter is empty or view != filter, show all
        hostdata_sql = 'select hosts.id as hid, ipv4, ipv6, fqdn, os, host_notes.id as note_id\
                        from hosts\
                          left join host_notes on host_notes.host_id = hosts.id\
                          right join services on hosts.id = services.host_id\
                        where engagement_id = %s order by ipv4 asc limit 1000'
        prm = [eid]

    qry = db_getdict(hostdata_sql, tuple(prm))
    if qry['success']:
        if qry['data']:
            hostdata = qry['data']
        else:
            logger.debug('no hosts found, returning empty result set')
            return result
    else:
        frameinfo = getframeinfo(currentframe())
        where = frameinfo.filename + ':' + str(frameinfo.lineno)
        logger.error(where + ': hosts query failed')
        return result

    if len(hostdata) == 1000:
        flash('Displaying first 1000 results, please use filtering to find hosts or services', 'info')

    # dictify hosts by host id
    hosts = { i.pop('hid'): i for i in hostdata }

    # get virthosts
    qry = db_getdict('select host_id, virthost from http_virthost where host_id in (select id from hosts where engagement_id = %s)',
                             (eid,))
    vhostdata = qry['data'] if qry['data'] else {}
    for vhost in vhostdata:
        # when showing a view other than 'full' some hosts will be filtered out
        if vhost['host_id'] in hosts:
            hosts[vhost['host_id']].setdefault('vhosts', []).append(vhost['virthost'])
            #logger.debug('added vhost ' + vhost['virthost'] + ' for hostid ' + str(vhost['host_id']))

    servicedata_sql = 'select services.id, host_id, cert_cn, protocol, port, service, webappurl, software, software_favicon,\
                              embedded_server::int, phpmyadmin, drupal_detected, wordpress_detected, python_detected,\
                              dotnet_handlers, php_version, nessus_errors.id as error_id\
                       from services\
                            left join nessus_errors on services.id = nessus_errors.service_id'
    if host_id_list:
        servicedata_sql += " where host_id in ('" + "','".join(host_id_list) + "')"
        prm = []
    else:
        servicedata_sql += ' where host_id in (select id from hosts where engagement_id = %s)'
        prm = [eid]

    servicedata_sql += " order by protocol asc, port asc"
    qry = db_getdict(servicedata_sql, tuple(prm))

    # dictify services by host id -> service id
    servicedata = qry['data'] if qry['data'] else []
    services = {}
    svcmap = {}
    for i, s in enumerate(servicedata):
        hid = s.pop('host_id')
        # this needs to be a list to enable listing host ports in numeric order
        # services are stored unique by protocol, port, webappurl to allow tracking vhost specific vulns - causing duplicates
        # collect protoport, hid, pos within hid so duplicate entries can be found
        # collect svcname and webappurl so we know how to update duplicates
        svckey = s['protocol'] + str(s['port'])
        if hid in svcmap:
            if svckey in svcmap[hid]:
                mapped_svc = svcmap[hid][svckey]
                if s['service'] and (mapped_svc['service'] == 'unknown' or not mapped_svc['service']):
                    services[hid][ mapped_svc['pos'] ]['service'] = s['service']

                for key in ['webappurl', 'cert_cn', 'protocol', 'port', 'service', 'webappurl', 'software', 'software_favicon',
                            'embedded_server', 'phpmyadmin', 'drupal_detected', 'wordpress_detected', 'python_detected',
                            'dotnet_handlers', 'php_version']:

                    if s[key] and not mapped_svc[key]:
                        services[hid][ mapped_svc['pos'] ][key] = s[key]

            else:
                services.setdefault(hid, []).append(s)
                svcmap[hid][svckey] = {'pos': len(services[hid]) - 1} | s
        else:
            services.setdefault(hid, []).append(s)
            svcmap[hid] = { svckey: {'pos': len(services[hid]) - 1} | s }

    if host_id_list:
        qry = db_getdict("select findings.id as vid, service_id as sid, severity, count(severity) as count\
                          from findings join issues_seen on issue_id = issues_seen.id\
                          where service_id in (select id from services where host_id in ('" + "','".join(host_id_list) + "'))\
                            and severity != 0\
                          group by findings.id, service_id, severity")
    else:
        qry = db_getdict('select findings.id as vid, service_id sid, severity, count(severity) as count\
                          from findings join issues_seen on issue_id = issues_seen.id\
                          where engagement_id = %s and severity != 0\
                          group by findings.id, service_id, severity', (eid,))

    vulndata = qry['data'] if qry['data'] else {}
    # dictify vulns by service id -> vuln id (often multiple vulns per service)
    vulns = {}
    for vuln in vulndata:
        vid = vuln.pop('vid')
        sid = vuln.pop('sid')

        if sid in vulns:
            vulns[sid][vid] = vuln
        else:
            vulns[sid] = {vid: vuln}

    # compile final dataset
    logger.debug('collected data, compiling response')
    for hid in hosts:
        #'main_colset':   [ 'hostinf', 'portinf', 'softinf', 'vulninf', 'errors'] }
        hostentry = { 'first_row': [], 'rows': [], 'hid': hid }

        hostinf = [ hosts[hid][i] for i in ['ipv4', 'ipv6', 'fqdn'] if hosts[hid][i] ]

        #if there's vhosts data, insert the extra hostnames after fqdn
        if 'vhosts' in hosts[hid]:
            for vhost in hosts[hid]['vhosts']:
                if vhost in hostinf:
                    continue
                else:
                    hostinf.append(vhost)
                    #logger.debug('added vhost to hostinf: ' + vhost)

        if hosts[hid]['os']:
            hostinf += hosts[hid]['os'].split('|')

        hostentry['first_row'].append(hostinf)

        if hid in services:
            for n, svc in enumerate(services[hid]):
                row = []
                sid = svc['id']
                port = svc['port']
                protocol = svc['protocol']
                portstr = str(protocol) + '/' + str(port)
                webappurl = svc['webappurl']
                svc_name = svc['service']
                service = webappurl if webappurl and re.search('/', webappurl) else svc_name

                # add value for the port cell (as array for consistency)
                row.append([portstr])
                row.append([service])

                softinf = [svc[i] for i in ['software', 'software_favicon', 'phpmyadmin', 'wordpress_detected',
                                            'drupal_detected', 'python_detected', 'php_version'] if svc[i] ]
                # value of 'embedded_server' is True/False so can't be added in the loop above
                if svc['embedded_server']:
                    softinf.append('embedded server')

                # add array of values for the software cell
                row.append(softinf)

                # if this service has vulns
                if sid in vulns:
                    cvulns = {}
                    # loop through them and create a summary
                    for vid in vulns[sid]:
                        severity = severity_map[vulns[sid][vid]['severity']]
                        if severity not in cvulns:
                            cvulns.setdefault(severity, int(vulns[sid][vid]['count']))
                        else:
                            cvulns[severity] += int(vulns[sid][vid]['count'])

                    vulninf = [str(v) + '\xa0' + k for k, v in cvulns.items()]
                    # add array of values for the vulns cell
                    row.append(vulninf)
                else:
                    # add empty array for the vulns cell if no vulns
                    row.append([])

                if svc['error_id']:
                    row.append([str(svc['error_id'])])
                else:
                    # add empty array for the errors cell if no vulns
                    row.append([])

                if n == 0:
                    #logger.debug('first row is ' + repr(hostentry['first_row']) + ' appenidng ' + repr(row))
                    hostentry['first_row'] += row
                    #logger.debug('first row now is: ' + repr(hostentry['first_row']))
                else:
                    #logger.debug('appending row: ' + repr(row))
                    hostentry['rows'].append(row)

        else:
            #logger.debug('first row is ' + repr(hostentry['first_row']) + ' appenidng []')
            hostentry['first_row'].append([]) # empty portstr
            hostentry['first_row'].append([]) # empty softinf
            hostentry['first_row'].append([]) # empty vulninf
            hostentry['first_row'].append([]) # empty errors
            #logger.debug('first row now is: ' + repr(hostentry['first_row']))

        result['data'].append(hostentry)

    #logger.debug(repr(result['data']))
    return result

def import_file(filename, scan_type=None, eid=None):
    start_time = time.time()
    status = None
    if not scan_type:
        scan_type = request.form['scantype']
    if not eid:
        eid, eng_type = get_engagement_id(test_type=True)
    if filename:
        logger.info('importing: ' + filename)
        with open(filename, 'r') as f:
            for line in islice(f, 10):
                if line.startswith('<NessusClientData_v2>'):
                    logger.debug('nessus report recognised')
                    try:
                        status = xhq.nessus.import_scan(filename, scan_type, eid, eng_type)
                        break
                    except Exception as e:
                        logger.error(repr(e))
                        logerror(__name__, getframeinfo(currentframe()).lineno, 'nessus import failed')
                        #raise
                        return {'error': 'Error processing XML'}

                elif eng_type != 'audit':
                    logger.debug('not an audit')
                    if re.search('https://raw.githubusercontent.com/placeholder/scnr/', line):
                        logger.debug('scnr report recognised')
                        try:
                            status = xhq.scnr.import_scan(filename, scan_type, eid)
                            break
                        except Exception as e:
                            logger.error(repr(e))
                            logerror(__name__, getframeinfo(currentframe()).lineno, 'scnr import failed')
                            #raise
                            return {'error': 'Error processing XML'}
                    elif re.search('<invicti-enterprise generated', line):
                        logger.debug('netsparker report recognised')
                        try:
                            status = xhq.netsparker.import_scan(filename, scan_type, eid)
                            break
                        except Exception as e:
                            logger.error(repr(e))
                            logerror(__name__, getframeinfo(currentframe()).lineno, 'netsparker import failed')
                            #raise
                            return {'error': 'Error processing XML'}

                    elif re.search(r'PingCastle', line):
                        logger.debug('pingcastle report recognised')
                        # always internal
                        try:
                            status = xhq.pingcastle.import_scan(filename, eid)
                            break
                        except Exception as e:
                            logger.error(repr(e))
                            logerror(__name__, getframeinfo(currentframe()).lineno, 'pingcastle import failed')
                            #raise
                            return {'error': 'Import error'}

                    elif re.search(r'nmaprun', line):
                        logger.debug('nmap data recognised')
                        try:
                            status = xhq.nmap.import_scan(filename, scan_type, eid)
                            break
                        except Exception as e:
                            logger.error(repr(e))
                            logerror(__name__, getframeinfo(currentframe()).lineno, 'nmap import failed')
                            #raise
                            return {'error': 'Error processing XML'}

                    elif re.search(r'burpVersion', line):
                        logger.debug('burp data recognised, parsing ' + filename + ' for ' + scan_type + ' engagement id ' + str(eid))
                        try:
                            status = xhq.burp.import_scan(filename, scan_type, eid)
                            break
                        except Exception as e:
                            logger.error(repr(e))
                            logerror(__name__, getframeinfo(currentframe()).lineno, 'burp import failed')
                            #raise
                            return {'error': 'Error processing XML'}

                    elif re.search(r'<ScanGroup ExportedOn', line):
                        logger.debug('acunetix data recognised, parsing ' + filename + ' for ' + scan_type + ' engagement id ' + str(eid))
                        try:
                            status = xhq.acunetix.import_scan(filename, scan_type, eid)
                            break
                        except Exception as e:
                            logger.error(repr(e))
                            logerror(__name__, getframeinfo(currentframe()).lineno, 'acunetix import failed')
                            #raise
                            return {'error': 'Error processing XML'}
                    elif re.search(r'qualysguard', line):
                        logger.debug('qualys data recognised, parsing ' + filename + ' for ' + scan_type + ' engagement id ' + str(eid))
                        try:
                            status = xhq.qualys.import_scan(filename, scan_type, eid)
                            break
                        except Exception as e:
                            logger.error(repr(e))
                            logerror(__name__, getframeinfo(currentframe()).lineno, 'qualys import failed')
                            #raise
                            return {'error': 'Error processing XML'}
                    elif re.search(r'OWASPZAPReport', line):
                        logger.debug('ZAP data recognised, parsing {} for {} engagement id {}'.format(filename, scan_type, eid))
                        try:
                            status = xhq.zap.import_scan(filename, scan_type, eid)
                            break
                        except Exception as e:
                            logger.error(repr(e))
                            logerror(__name__, getframeinfo(currentframe()).lineno, 'zap import failed')
                            #raise
                            return {'error': 'Error processing XML'}
            else:
                if not status:
                    if eng_type != 'audit':
                        # try to import it as fqdn / ip pairs e.g. amass output
                        logger.warning('could not recognise ' + filename + ' attempting amass import')
                        try:
                            status = xhq.amass.import_scan(filename, eid)
                        except Exception as e:
                            logger.error(repr(e))
                            logerror(__name__, getframeinfo(currentframe()).lineno, 'amass import failed')
                            return {'error': 'Error processing ' + filename}
                    else:
                        status = {'error': 'Audit engagements support only Nessus audit scans at present'}
                        logger.debug(status['error'])

    if status and not status['error']:
        os.remove(filename)
        qry = db_do('update engagements set summarised = false where eid = %s', (eid,))
        status['import_time'] = str(round((time.time() - start_time), 1))
        logger.info('file imported in ' + status['import_time'])
        if not qry['success']:
            logger.error('failed to update summarised flag')
            flash('Server error: failed to update summarisation status')

    return status

def delete_scan_services(scanner, _id, eid, curs):
    scan_uri = scanner + '/' + _id
    logger.debug('processing scan for deletion: ' + scan_uri)
    qry = db_getdict('select id::text, scan_uri_list, external from services where scan_uri_list like %s',
                            ('%' + scan_uri + '%',))

    services = qry['data'] if qry['data'] else {}
    service_id_list = [s['id'] for s in services]
    service_id_str = ','.join(service_id_list)

    qry = db_getdict('select id::text, service_id::text, scan_uri_list, external\
                      from findings where service_id in (' + service_id_str + ')')
    findings = qry['data'] if qry['data'] else {}
    svc_findings = {}
    for f in findings:
        service_id = str(f.pop('service_id'))
        svc_findings.setdefault(service_id, []).append(f)

    scans = get_imported_scans(eid)
    exposuremap = { s['scanner'] + '/' + s['id']: s['scan_type'] for s in scans }
    logger.debug(repr(exposuremap))

    services2delete = []
    findings2delete = []
    hosts2check = []
    for svc in services:
        service_id = svc['id']
        scan_uri_list = svc['scan_uri_list']
        logger.debug('checking ' + svc['id'] + '/' + scan_uri_list)
        scan_uri_set = set(scan_uri_list.split(','))
        scan_uri_set.remove(scan_uri)
        if scan_uri_set:
            scan_uri_str = ','.join(scan_uri_set)
            update_cols = ['scan_uri_list']
            update_vals = [scan_uri_str]
            svc_is_external = False
            if svc['external']:
                # if the service is currently marked as externally exposed, check if any of the remaining scans are external
                for _scan_uri in scan_uri_set:
                    if exposuremap[_scan_uri] == 'external':
                        svc_is_external = True
                        break
                else:
                    logger.debug('remaining scans for external service are internal only, updating exposure')
                    update_cols.append('external')
                    update_vals.append(False)

            logger.debug('updating service: ' + str(service_id) + '/' + scan_uri_str)
            sql = get_pg_update_sql('services', update_cols, 'where id = %s')
            update_vals.append(service_id)
            curs.execute(sql, tuple(update_vals))
            # update findings
            if service_id in svc_findings:
                for f in svc_findings[service_id]:
                    scan_uri_list = f['scan_uri_list'].split(',')
                    if scan_uri in scan_uri_list:
                        scan_uri_list.remove(scan_uri)

                    if scan_uri_list:
                        update_cols = ['scan_uri_list']
                        update_vals = [','.join(scan_uri_list)]
                        # an external service could have internal only findings (through layer 4 and up firewalls)
                        # but an internal service can never have external findings
                        if f['external'] and not svc_is_external:
                            logger.debug('service is internal, updating finding exposure for id ' + str(f['id']))
                            update_cols.append('external')
                            update_vals.append(False)

                        sql = get_pg_update_sql('findings', update_cols, 'where id = %s')
                        update_vals.append(f['id'])
                        curs.execute(sql, tuple(update_vals))
                    else:
                        logger.debug('queue finding for deletion: ' + str(f['id']))
                        findings2delete.append(f['id'])

        else:
            logger.debug('queue service for deletion: ' + str(service_id))
            services2delete.append(str(service_id))

    if findings2delete:
        findings_str = "'" + "','".join(findings2delete) + "'"
        curs.execute('delete from findings where id in (' + findings_str + ')')
        logger.debug('deleted findings: ' + findings_str)

    if services2delete:
        svc_str = "'" + "','".join(services2delete) + "'"
        curs.execute('delete from services where id in (' + svc_str + ')')
        #logger.debug('deleted services: ' + svc_str)

    logger.debug('deleting hosts with no remaining services')
    curs.execute('delete from hosts where engagement_id = %s and id not in (select host_id from services)', (eid,))

    return True

def delete_scan(scan_id):
    eid = get_engagement_id()
    scanner, _id = scan_id.split('/')
    if scanner not in supported_scanners:
        logger.error('bad scanner value in delete_scan request: {}'.format(scanner))
        return False

    if not re.match('^\d+$', _id):
        logger.warn('bad scan id: {}'.format(_id))
        return False

    qry = db_getcol('select id from ' + scanner + '_scans where id = %s and engagement_id = %s', (_id, eid))
    if qry['success']:
        if qry['data']:
            logger.debug('ownership verified, deleting ' + scanner + ' scan id: ' + _id)
        else:
            logger.warn('refusing to delete: scan id ' + str(_id)  + ' is not part of engagement ' + str(eid))
            return False

        conn = get_db()
        curs = conn.cursor()
        # filename in db contains path info (../xml/filename) so query matches the end only
        if delete_scan_services(scanner, _id, eid, curs):
            table = scanner + '_scans'
            try:
                curs.execute('delete from ' + table + ' where id = %s', (_id, ))
                curs.execute('update engagements set summarised = false where eid = %s', (eid,))
                conn.commit()
            except Exception as e:
                logger.error(e.pgerror)
                logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to delete imported scan')
                conn.close()
                return False

            conn.close()
            return True
        else:
            conn.close()
    else:
        logger.error('failed to verify scan ownership, query error')

    return False

def get_hostlist(args, idlist=False):
    user_id = session['user_id']
    eid = get_engagement_id()
    term = args['host']

    keywords = ['internal', 'external', 'private', 'public']
    if term == '':
        return keywords

    result = []
    if idlist:
        logger.debug('getting host idlist for term ' + term)
        if term in ['public', 'private']:
            sql = 'select id::text, ipv4 from hosts where engagement_id = %s'
            prm = [eid]

        elif term in ['internal', 'external']:
            isexternal = 'true' if term == 'external' else 'false'
            sql = 'select id::text from hosts where engagement_id = %s\
                                                and id in (select host_id from services where external is ' + isexternal +')'
            prm = [eid]

        else:
            term = '%' + str(term) + '%'
            sql = 'select id::text from hosts where engagement_id = %s\
                                                and (ipv4::text like %s or ipv6::text like %s\
                                                     or lower(os) like lower(%s) or lower(fqdn) like lower(%s))\
                    union select host_id::text from http_virthost where host_id in (select id from hosts where engagement_id = %s)\
                                                                  and lower(virthost) like lower(%s)'
            prm = [eid] + [term] * 4 + [eid, term]

        if term in ['public', 'private']:
            qry = db_getdict(sql, tuple(prm))
            if not qry['success']:
                logger.error('query failed')
            data = qry['data']
            private_subnets = [ipaddress.ip_network(n) for n in ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']]
            for host in data:
                public = True
                for subnet in private_subnets:
                    ip = ipaddress.ip_address(host['ipv4'])
                    if ip in subnet:
                        if term == 'private':
                            result.append(host['id'])
                        else:
                            public = False

                        break

                #NOTE this ignores multicast etc ranges, that seems acceptable right now
                if term == 'public' and public :
                    result.append(host['id'])
        else:
            logger.debug(sql)
            qry = db_getcol(sql, tuple(prm))
            if not qry['success']:
                logger.error('query failed')
            else:
                logger.debug('host idlist contains ' + str(len(qry['data'])))
                result = qry['data']

        return result
    else:
        logger.debug('compiling autocomplete suggestions for host/ip matching ' + term)
        for word in keywords:
            if word.lower().startswith(term):
                result.append(word.lower())

        # check additional (non-host) filters to define a host shortlist
        # if at any step the shortlist becomes zero, fail early & return an empty result set
        host_id_list = set()
        if 'port' in args and args['port']:
            host_id_list = set(get_portlist(args, idlist=True))
            logger.debug('port filter specified, returned ' + str(len(host_id_list)))
            if not host_id_list:
                return result

        if 'service' in args and args['service']:
            servicelist = set(get_servicelist(args, idlist=True))
            logger.debug('service filter specified, returned ' + str(len(servicelist)))
            if servicelist:
                host_id_list = host_id_list & servicelist if host_id_list else servicelist
                logger.debug('new host list size: ' + str(len(host_id_list)))
                if not host_id_list:
                    return result
            else:
                return result

        if 'software' in args and args['software']:
            softwarelist = set(get_softwarelist(args, idlist=True))
            logger.debug('software filter specified, returned ' + str(len(softwarelist)))
            if softwarelist:
                host_id_list = host_id_list & softwarelist if host_id_list else softwarelist
                logger.debug('new host list size: ' + str(len(host_id_list)))
                if not host_id_list:
                    return result
            else:
                return result

        if 'findings' in args and args['findings']:
            findingslist = set(get_vulnlist(args, idlist=True))
            logger.debug('findings filter specified, returned ' + str(len(findingslist)))
            if findingslist:
                host_id_list = host_id_list & findingslist if host_id_list else findingslist
                logger.debug('new host list size: ' + str(len(host_id_list)))
                if not host_id_list:
                    return result
            else:
                return result

        term = '%' + str(term) + '%'
        if host_id_list:
            logger.debug('using host shortlist of ' + str(len(host_id_list)))
            hoststr = "('" + "','".join(host_id_list) + "')"
            sql = "select substring(ipv4::text from '^[^/]+') as ipqdn from hosts where id in "+ hoststr +" and ipv4::text like %s\
                    union select substring(ipv6::text from '^[^/]+') from hosts where id in "+ hoststr +" and ipv6::text like %s\
                    union select os from hosts where id in " + hoststr + " and lower(os) like lower(%s)\
                    union select fqdn from hosts where id in "+ hoststr +" and lower(fqdn) like lower(%s)\
                    union select virthost from http_virthost where host_id in "+ hoststr +" and lower(virthost) like lower(%s)"
            prm = [term] * 5

        else:
            sql = "select substring(ipv4::text from '^[^/]+') as ipqdn from hosts where engagement_id = %s and ipv4::text like %s\
                    union select substring(ipv6::text from '^[^/]+') from hosts where engagement_id = %s and ipv6::text like %s\
                    union select os from hosts where engagement_id = %s and lower(os) like lower(%s)\
                    union select fqdn from hosts where engagement_id = %s and lower(fqdn) like lower(%s)\
                    union select virthost from http_virthost where host_id in (select id from hosts where engagement_id = %s)\
                                                              and lower(virthost) like lower(%s)"
            prm = [eid, term] * 5

        qry = db_getcol(sql, tuple(prm))
        if qry['success']:
            data = qry['data']
            if data:
                for i, item in enumerate(data):
                    if re.search('\|', item):
                        expanded = data[i].split('|')

                        matches = []
                        for x in expanded:
                            if re.search(term.strip('%'), x, re.IGNORECASE):
                                matches.append(x)
                        # if there is more than one match leave the entry as is
                        if len(matches) == 1:
                            data[i] = matches[0]

                result += data
                result = list(set(result))

        if result:
            logger.debug('total autocomplete entries: ' + str(len(result)))
            #result.sort()

        return result

def get_portlist(args, idlist=False):
    term = args['port']

    if term == '*':
        proto_term = '*'
        port_term = None
    elif re.search('/', term):
        proto_term, port_term = term.split('/')
    elif re.match('^[a-zA-Z]+$', term):
        proto_term = term
        port_term = None
    elif re.match('^\d+$', term):
        proto_term = None
        port_term = term
    else:
        logger.info('ignoring port search, failed to match term ' + str(term))
        return None

    user_id = session['user_id']
    eid = get_engagement_id()

    result = []
    ## get list for ports matching term
    if idlist:
        # idlist does no additional filtering
        logger.debug('compiling host id list for port matching ' + term)
        sql = 'select host_id::text from services where host_id in (select id from hosts where engagement_id = %s)'
        prm = [eid]

        if port_term:
            sql += ' and port::text like %s'
            prm.append('%' + port_term + '%')

        if proto_term and proto_term != '*':
            sql += ' and protocol like %s'
            prm.append('%' + proto_term + '%')

        sql += ' group by host_id'

        qry = db_getcol(sql, tuple(prm))
        return qry['data']

    else:
        logger.debug('compiling autocomplete suggestions for port matching ' + term + '(' + repr((port_term, proto_term)))
        # check additional (non-port) filters to define a host shortlist
        # if at any step the shortlist becomes zero, fail early & return an empty result set
        host_id_list = []
        if 'host' in args and args['host']:
            host_id_list = set(get_hostlist(args, idlist = True))
            if not host_id_list:
                logger.debug('empty list from get_hostlist')
                return result

        if 'service' in args and args['service']:
            servicelist = set(get_servicelist(args, idlist = True))
            if servicelist:
                host_id_list = host_id_list & servicelist if host_id_list else servicelist
                if not host_id_list:
                    logger.debug('empty list from get_servicelist')
                    return result
            else:
                return result

        if 'software' in args and args['software']:
            softwarelist = set(get_softwarelist(args, idlist=True))
            if softwarelist:
                host_id_list = host_id_list & softwarelist if host_id_list else softwarelist
                if not host_id_list:
                    return result
            else:
                return result

        if 'findings' in args and args['findings']:
            findingslist = set(get_vulnlist(args, idlist=True))
            if findingslist:
                host_id_list = host_id_list & findingslist if host_id_list else findingslist
                if not host_id_list:
                    return result
            else:
                return result

        if host_id_list:
            sql = "select protocol, port from services where host_id in ('" + "','".join(host_id_list) + "')"
            prm = []
        else:
            sql = 'select protocol, port from services where host_id in (select id from hosts where engagement_id = %s)'
            prm = [eid]

    if proto_term == '*':
        logger.debug('getting full protocol and port list for wildcard search')
    else:
        if proto_term:
            logger.debug('getting list for protocols matching ' + proto_term)
            proto_term = '%' + str(proto_term) + '%'
            sql += ' and protocol like %s'
            prm.append(proto_term)

        if port_term:
            logger.debug('getting list for port matching ' + port_term)
            port_term = '%' + str(port_term) + '%'
            sql += ' and port::text like %s'
            prm.append(port_term)

    sql += ' group by protocol, port order by protocol asc, port asc'
    qry = db_getdict(sql, tuple(prm))
    if not qry['success']:
        logger.error('query failed')

    portlist = qry['data']

    return [ service['protocol'] + '/' + str(service['port']) for service in qry['data'] ]

def get_servicelist(args, idlist=False):
    user_id = session['user_id']
    eid = get_engagement_id()
    term = args['service']

    result = []
    ## get list for ports matching term
    if idlist:
        # idlist does no additional filtering
        logger.debug('compiling host id list for services matching ' + term)
        sql = 'select host_id::text from services\
               where host_id in (select id from hosts where engagement_id = %s)'
        prm = [eid]
        if term != '*':
            sql += ' and service like %s'
            prm.append(term)

        sql += ' group by host_id'

        qry = db_getcol(sql, tuple(prm))
        return qry['data']
    else:
        host_id_list = []
        if 'host' in args and args['host']:
            host_id_list = set(get_hostlist(args, idlist = True))
            if not host_id_list:
                return result

        if 'port' in args and args['port']:
            portlist = set(get_portlist(args, idlist = True))
            if portlist:
                host_id_list = host_id_list & portlist if host_id_list else portlist
                if not host_id_list:
                    return result
            else:
                return result

        if 'software' in args and args['software']:
            softwarelist = set(get_softwarelist(args, idlist=True))
            if softwarelist:
                host_id_list = host_id_list & softwarelist if host_id_list else softwarelist
                if not host_id_list:
                    return result
            else:
                return result

        if 'findings' in args and args['findings']:
            findingslist = set(get_vulnlist(args, idlist=True))
            if findingslist:
                host_id_list = host_id_list & findingslist if host_id_list else findingslist
                if not host_id_list:
                    return result
            else:
                return result

        if host_id_list:
            sql = "select service from services where host_id in ('" + "','".join(host_id_list) + "') and service is not null"
            prm = []
        else:
            sql = "select service from services where host_id in (select id from hosts where engagement_id = %s) and service is not null"
            prm = [eid]

        if term == '*':
            logger.debug('wildcard search, no additional filtering')
        else:
            termlist = term.split('|')
            logger.debug('split term with | to ' + repr(termlist))
            sql += ' and ('
            for i, t in enumerate(termlist):
                sql += ' lower(service) like lower(%s) or' if i < len(termlist) - 1 else ' lower(service) like lower(%s)'
                prm.append('%' + t + '%')
            sql += ')'

        sql += ' group by service order by service asc'

    qry = db_getcol(sql, tuple(prm))
    if not qry['success']:
        logger.error('query failed')

    return qry['data']

def get_softwarelist(args, idlist=False):
    user_id = session['user_id']
    eid = get_engagement_id()
    term = args['software']
    if term != '*':
        term = '%' + term + '%'

    # define base query
    if idlist:
        logger.debug('getting service idlist for ' + term)
        sql = 'select host_id::text from services where host_id in (select id from hosts where engagement_id = %s)'
        prm = [eid]

        if term != '*':
            sql += ' and (lower(software) like lower(%s) or\
                          lower(software_favicon) like lower(%s) or\
                          lower(phpmyadmin) like lower(%s) or\
                          lower(drupal_detected) like lower(%s) or\
                          lower(wordpress_detected) like lower(%s) or\
                          lower(python_detected) like lower(%s) or\
                          lower(dotnet_handlers) like lower(%s) or\
                          lower(php_version) like lower(%s)'
            prm += [term] * 8

            try:
                if re.search(term, 'embedded server'):
                    logger.debug('search term applies to embedded server')
                    sql += ' or embedded_server is true)'
                else:
                    sql += ')'
            except:
                logger.debug('search term contains unescaped regex chars, ignoring')
                sql += ')'

        sql += ' group by host_id'
        qry = db_getcol(sql, tuple(prm))
        if not qry['success']:
            logger.error('query failed')

        return qry['data']
    else:
        result = []
        logger.debug('getting service namelist for ' + term)
        host_id_list = []
        if 'host' in args and args['host']:
            host_id_list = set(get_hostlist(args, idlist = True))
            if not host_id_list:
                logger.debug('host filter returned an empty list')
                return result
            else:
                logger.debug('host filter returned a list of ' + str(len(host_id_list)))

        if 'port' in args and args['port']:
            portlist = set(get_portlist(args, idlist = True))
            if portlist:
                host_id_list = host_id_list & portlist if host_id_list else portlist
                if not host_id_list:
                    logger.debug('idlist empty after applying port filter')
                    return result
                else:
                    logger.debug('port filter returned a list of ' + str(len(host_id_list)))
            else:
                logger.debug('port filter returned an empty list')
                return result

        if 'service' in args and args['service']:
            servicelist = set(get_servicelist(args, idlist=True))
            if servicelist:
                host_id_list = host_id_list & servicelist if host_id_list else servicelist
                if not host_id_list:
                    logger.debug('idlist empty after applying service filter')
                    return result
                else:
                    logger.debug('service filter returned a list of ' + str(len(host_id_list)))
            else:
                logger.debug('service filter returned an empty list')
                return result

        if 'findings' in args and args['findings']:
            findingslist = set(get_vulnlist(args, idlist=True))
            if findingslist:
                host_id_list = host_id_list & findingslist if host_id_list else findingslist
                if not host_id_list:
                    logger.debug('idlist empty after applying findings filter')
                    return result
                else:
                    logger.debug('findings filter returned a list of ' + str(len(host_id_list)))
            else:
                logger.debug('findings filter returned an empty list')
                return result

        if host_id_list:
            logger.debug('getting software data for a list of ' + str(len(host_id_list)))
            sql = "select software, software_favicon, phpmyadmin, drupal_detected,\
                          wordpress_detected, python_detected, dotnet_handlers, php_version\
                   from services where host_id in ('" + "','".join(host_id_list) + "')"
            prm = []
        else:
            logger.debug('getting software data for all services in the engagement')
            sql = 'select software, software_favicon, phpmyadmin, drupal_detected,\
                          wordpress_detected, python_detected, dotnet_handlers, php_version\
                   from services where host_id in (select id from hosts where engagement_id = %s)'
            prm = [eid]

        if term == '*':
            logger.debug('search term is a wildcard')
        else:
            sql += ' and (lower(software) like lower(%s) or\
                          lower(software_favicon) like lower(%s) or\
                          lower(phpmyadmin) like lower(%s) or\
                          lower(drupal_detected) like lower(%s) or\
                          lower(wordpress_detected) like lower(%s) or\
                          lower(python_detected) like lower(%s) or\
                          lower(dotnet_handlers) like lower(%s) or\
                          lower(php_version) like lower(%s)'
            prm += [term] * 8

            try:
                if re.search(term, 'embedded server'):
                    logger.debug('search term applies to embedded server')
                    sql += ' or embedded_server is true)'
                else:
                    sql += ')'
            except:
                logger.debug('search term contains unescaped regex chars, ignoring')
                sql += ')'

        qry = db_getdict(sql, tuple(prm))
        if qry['success']:
            if qry['data']:
                logger.debug('got a list of ' + str(len(qry['data'])) + ' software names')
            else:
                logger.debug('got a list of 0 software names')
        else:
            logger.error('query failed')

    result = set()
    for service in qry['data']:
        for fld in ['software', 'software_favicon', 'phpmyadmin', 'drupal_detected',
                    'wordpress_detected', 'python_detected', 'dotnet_handlers', 'php_version']:
            term = term.strip('%')
            if term == '*':
                if service[fld]:
                    result.add(service[fld].strip())
            else:
                if service[fld] and re.search(term, service[fld], re.IGNORECASE):
                    logger.debug(service[fld])
                    result.add(service[fld].strip())

    result = list(result)
    return result

def get_vulnlist(args, idlist=False):
    term = args['findings']
    logger.debug('getting vulnerability list for ' + str(term))

    user_id = session['user_id']
    eid = get_engagement_id()
    severity_dict = { 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical' }

    search_prm = []
    if term != '*':
        termlist = term.split('|')
        logger.debug('split term with | to ' + repr(termlist))
        search_sql = ' and ('
        for i, t in enumerate(termlist):
            severity = None
            for k,v in severity_dict.items():
                if v.lower().startswith(t.lower()):
                    severity = k
                    break

            if severity:
                search_sql += ' severity = %s or' if i < len(termlist) - 1 else ' severity = %s'
                search_prm.append(severity)

        search_sql += ')'
    else:
        search_sql = None

    if idlist:
        # idlist does no additional filtering
        logger.debug('compiling host id list for severities matching ' + term)
        sql = 'select host_id::text from findings join services on service_id = services.id\
                                                  join issues_seen on issue_id = issues_seen.id\
               where engagement_id = %s'
        prm = [eid]
        if search_sql:
            sql += search_sql
            prm += search_prm

        sql += ' group by host_id'

        qry = db_getcol(sql, tuple(prm))
        return qry['data']
    else:
        result = []
        host_id_list = set()
        if 'host' in args and args['host']:
            host_id_list = set(get_hostlist(args, idlist = True))
            if not host_id_list:
                logger.debug('host filter returned an empty list')
                return result
            else:
                logger.debug('host filter returned a list of ' + str(len(host_id_list)))

        if 'port' in args and args['port']:
            portlist = set(get_portlist(args, idlist = True))
            if portlist:
                host_id_list = host_id_list & portlist if host_id_list else portlist
                if not host_id_list:
                    logger.debug('idlist empty after applying port filter')
                    return result
                else:
                    logger.debug('port filter returned a list of ' + str(len(host_id_list)))
            else:
                logger.debug('port filter returned an empty list')
                return result

        if 'service' in args and args['service']:
            servicelist = set(get_servicelist(args, idlist=True))
            if servicelist:
                host_id_list = host_id_list & servicelist if host_id_list else servicelist
                if not host_id_list:
                    logger.debug('idlist empty after applying service filter')
                    return result
                else:
                    logger.debug('service filter returned a list of ' + str(len(host_id_list)))
            else:
                logger.debug('service filter returned an empty list')
                return result

        if 'software' in args and args['software']:
            softwarelist = set(get_softwarelist(args, idlist=True))
            if softwarelist:
                host_id_list = host_id_list & softwarelist if host_id_list else softwarelist
                if not host_id_list:
                    logger.debug('idlist empty after applying software filter')
                    return result
                else:
                    logger.debug('software filter returned a list of ' + str(len(host_id_list)))
            else:
                logger.debug('software filter returned an empty list')
                return result

        if host_id_list:
            logger.debug('getting findings for a final list of ' + str(len(host_id_list)) + ' host ids')
            sql = "select severity from findings join services on service_id = services.id\
                                                 join issues_seen on issue_id = issues_seen.id\
                   where host_id in ('" + "','".join(host_id_list) + "') and severity > 0"
            prm = []

        else:
            logger.debug('getting findings for all host ids in engagment')
            sql = 'select severity from findings join services on service_id = services.id\
                                                 join issues_seen on issue_id = issues_seen.id\
                   where engagement_id = %s and severity > 0'
            prm = [eid]

        if search_sql:
            sql += search_sql
            prm += search_prm

        sql += ' group by severity order by severity desc'

        qry = db_getcol(sql, tuple(prm))
        if not qry['success']:
            logger.error('query failed')

    if idlist:
        result = qry['data']
    else:
        if qry['data']:
            result = [ severity_dict[n] for n in qry['data'] ]
        else:
            result = []

    return result

def queue_import(filename, filepath, filecount, mc):
    logger.debug('queueing ' + filename)
    msgkey = 'messages_' + str(session['user_id'])
    prockey = 'processing_' + str(session['user_id'])
    if int(filecount) == 1:
        logger.debug('single file upload, processing directly')
        result = xhq.hacking.import_file(filepath)
        if result['error']:
            logger.warn('error parsing file ' + filepath)
            if msgkey in mc:
                mc[msgkey] += '##' + filename + ': ' + result['error']
            else:
                mc[msgkey] = '##' + filename + ': ' + result['error']

        return result

    else:
        logger.debug('multiple files submitted: ' + str(filecount))

    if prockey in mc:
        logger.debug(filename + ': session processing - ' + repr(mc[prockey]))
        while mc[prockey]:
            time.sleep(1)
            logger.debug('waiting for processing')

    logger.debug('setting processing flag')
    mc[prockey] = filename

    if mc[prockey] == filename:
        logger.debug('processing ' + filename)
        result = import_file(filepath)
        mc[prockey] = False
        logger.debug('done processing ' + filename)
    else:
        logger.debug(filename + ': requeueing because of ' + repr(mc[prockey]))
        result = queue_import(filename, filepath, filecount, mc)

    if result['error']:
        logger.warn('error parsing file ' + filepath)
        mc[prockey] = False
        if msgkey in mc:
            mc[msgkey] += '##' + filename + ': ' + result['error']
        else:
            mc[msgkey] = '##' + filename + ': ' + result['error']

    return result

def get_iplist_txt(form):
    args = { k:v for k,v in form.items() if k != 'csrf_token' }

    logger.debug('exporting ip list to text file')
    fmap = {'host': get_hostlist, 'port': get_portlist, 'service': get_servicelist,
            'software': get_softwarelist, 'findings': get_vulnlist }
    host_id_list = set()
    for arg in args:
        if arg == 'csrf_token':
            continue
        elif args[arg]:
            logger.debug('adding filtering by ' + arg)
            if arg in fmap:
                templist = set(fmap[arg](args, idlist=True))

                if templist:
                    logger.debug('filtering by ' + arg + ' returned ' + str(len(templist)))
                    host_id_list = host_id_list & templist if host_id_list else templist
                    logger.debug('host_id_list now contains ' + str(len(host_id_list)))
                else:
                    logger.info(arg + ' returned an empty list')
            else:
                logerror(__name__, getframeinfo(currentframe()).lineno, arg + ' is not defined')
        else:
            logger.debug(arg + ' is empty, ignoring')

    proxy = io.StringIO()
    if host_id_list:
        logger.debug('got final list of ' + str(len(host_id_list)))
        qry = db_getcol("select coalesce(ipv4, ipv6) as ip from hosts where id in ('" + "','".join(host_id_list) + "') order by ip")
        if qry['success']:
            for ip in qry['data']:
                proxy.write(ip + '\n')
        else:
            logger.error('query failed')

    mem = io.BytesIO()
    mem.write(proxy.getvalue().encode())
    mem.seek(0)
    proxy.close()
    logger.debug('file created in memory, returning')
    return mem
