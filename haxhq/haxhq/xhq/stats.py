import re
import logging
from flask import session, request
from datetime import date, timedelta
from inspect import currentframe, getframeinfo
from xhq.pingcastle_config import pcastle_issues
from xhq.reporting import get_affected_services
from xhq.util import get_db, db_getrow, db_getcol, db_getdict, db_do, get_uniq_id, get_fingerprint, logerror

logger = logging.getLogger(__name__)
logger.setLevel('INFO')

def get_vulnstats():
    '''Given a date range, returns a list of vulnerabilities seen over the period and the % of hosts affected per vuln'''
    # get data by vuln by engagement
    # host/services_count = hosts/services affected by the vuln
    # total_hosts/services = total hosts/services scanned during the engagement
    status = {'error': False}
    today = date.today()

    # prepopulate the result with the static elements
    result = { 'page': 'stats', 'has_stats': True, 'user': session['nickname'], 'user_groups': session['user_groups'],
               'isadmin': session['isadmin'], 'vulnstat_cols': ['Title', 'Severity', 'Affected hosts', 'Affected members'],
               'filter': {}, 'hidden_fields': ['Submit', 'CSRF Token', 'Title', 'Exposure'] }

    orderby = request.args['orderby'] if 'orderby' in request.args else 'severity'
    exposure = request.args['exposure'] if 'exposure' in request.args else 'external'
    results_limit = request.args['results'] if 'results' in request.args else 100
    searchterm = request.args['title'] if 'title' in request.args else None
    if 'stat_from' in request.args and request.args['stat_from']:
        stat_from = request.args['stat_from']
    else:
        stat_from = (today - timedelta(days=365)).strftime("%d/%m/%Y")

    if 'stat_to' in request.args and request.args['stat_to']:
        stat_to = request.args['stat_to']
    else:
        stat_to = today.strftime("%d/%m/%Y")

    # sanitise results_limit value
    if results_limit == 'all':
        logger.debug('showing all results')
    elif re.match('^\d+$', str(results_limit)) and int(results_limit) <= 10000:
        logger.debug('showing top ' + str(results_limit) + ' results')
    else:
        status['error'] = 'invalid results limit supplied'
        logger.warning(status['error'] + ': ' + results_limit)
        return status

    #XXX unsafe use of orderby in sql query so it is important to sanitize it here
    valid_orderby = ['severity', 'host_count', 'member_count', 'title']
    if orderby not in valid_orderby:
        status['error'] = 'Invalid parameter to order by'
        logger.warning(status['error'] + ': ' + orderby)
        return status

    logger.debug('ordering by ' + orderby)
    ordermap = {'Title': 'title', 'Severity': 'severity', 'Affected hosts': 'host_count', 'Affected members': 'member_count'}
    ordermap_rev = {v: k for k, v in ordermap.items()}

    result = {**result, **{ 'orderby': orderby, 'ordermap': ordermap, 'ordermap_rev': ordermap_rev }}

    valid_orderby.remove(orderby)
    full_order_str = orderby + ' desc, ' + ' desc, '.join(valid_orderby)
    logger.debug(full_order_str)

    # get totals for all stored data
    qry = db_getrow('select sum(total_hosts) as total_hosts, count(engagement_hash) as total_members\
                     from eng_stats\
                     where eng_stats.date between %s and %s', (stat_from, stat_to))
    data = qry['data']
    total_hosts = data['total_hosts']
    total_members = data['total_members']
    logger.debug('total hosts: ' + str(total_hosts) + ', total members: ' + str(total_members) + '('+ stat_from +' - '+ stat_to +')' )

    # get the requested dataset
    sql = 'select title, severity, sum(host_count) as host_count,\
                  round((sum(host_count) / '+ str(total_hosts) +'.00 * 100), 2) as host_pct,\
                  count(distinct engagement_hash) as member_count,\
                  round(count(distinct engagement_hash) / '+ str(total_members) +'.00 * 100) as member_pct\
           from vuln_stats\
           join eng_stats on eng_id = eng_stats.id\
           join issues_seen on issue_id = issues_seen.id\
           where date between %s and %s'

    param = [stat_from, stat_to]
    if exposure != 'all':
            sql += ' and exposure = %s'
            param.append(exposure)

    if searchterm:
            sql += ' and lower(title) like lower(%s) '
            searchstr = "%" + searchterm.lower() + "%"
            param.append(searchstr)

    sql += 'group by title, severity\
            order by ' + full_order_str + ' desc'

    qry = db_getdict(sql, tuple(param))

    data = qry['data']
    if data:
        total_results  = len(data)
        if results_limit != 'all':
            data = data[:int(results_limit)]
    else:
        data = []
        total_results  = 0

    for vuln in data:
        vuln['host_count'] = str(vuln['host_count']) + ' (' + str(vuln['host_pct']) + '%)'
        vuln['member_count'] = str(vuln['member_count']) + ' (' + str(vuln['member_pct']) + '%)'
        del vuln['host_pct']
        del vuln['member_pct']

    result = result | { 'vulns': data, 'total_hosts': total_hosts, 'total_members': total_members,
                        'total_results': total_results, 'shown': len(data) }

    return (status, result)

def get_vulnsovertime(start_date, end_date):
    '''given a date range and data key (vuln name/severity), returns summary data per month'''

    qry = db_getdict('select severity, date, host_count, service_count, total_hosts, total_services\
                      from vuln_stats\
                        join eng_stats on eng_id = eng_stats.id\
                        join issues_seen on issue_id = issues_seen.id\
                      where eng_stats.date between %s and %s',
                       (start_date, end_date))

    return qry['data']

def export_stats(eid):
    """collects and anonymises data from an engagement and stores it in the stats/issues_seen tables. Does not require a session"""
    status = {'error': False}

    qry = db_getcol('select eng_end from engagements where eid = %s', (eid,))
    if qry['success']:
        date = qry['data'][0]
    else:
        logger.error('query failed')
        return False

    #TODO - finish here
    issues_data = db_getdict('select id, title, fingerprint from issues_seen')
    issues_seen = { i['title']: {'id':i['id'], 'fingerprint':i['fingerprint']} for i in issues_data } if issues_data else {}

    issue_data = db_getdict('select id, title, name, cvss, cvss3, cve, exposure, scanner\
                             from reporting where engagement_id = %s and severity > 0',
                             (eid,))
    issue_texts = db_getdict('select title, description, solution as remediation, severity, nessus_id, pingcastle_id, acunetix_id, burp_id\
                              from findings where engagement_id = %s and severity > 0',
                             (eid,))
    issue_texts = { i.pop('title'): i for i in issue_texts }

    total_hosts = db_getcol('select count(id) from hosts where engagement_id = %s', (eid,))[0]
    total_services = db_getcol('select count(id) from services\
                                 where host_id in (select id from hosts where engagement_id = %s)', (eid,))[0]

    engagement_hash = get_uniq_id(str(eid))
    conn = get_db()
    curs = conn.cursor()

    curs.execute('insert into eng_stats (engagement_hash, total_hosts, total_services, date) values (%s, %s, %s, %s) returning id',
                                        (engagement_hash, total_hosts, total_services, date))
    eng_id = curs.fetchone()

    for issue in issue_data:
        riid = issue['id']
        issue_title = issue['title']
        if issue_title in issue_texts:
            issue = issue | issue_texts[issue_title]
        # old engagements may not have a finding stored for manual issues
        else:
            logger.warn('skipping issue without finding ' + str(eng_id) + '/' + issue_title)
            continue

        fingerprint = get_fingerprint(issue)
        if not issue['scanner']:
            for scanner in ['nessus', 'acunetix', 'burp', 'pingcastle']:
                if issue[scanner + '_id']:
                    issue['scanner'] = scanner
                    break
        if not issue['scanner']:
            issue['scanner'] = 'manual'

        if issue['scanner'] == 'pingcastle':
            for pcissue in pcastle_issues: 
                key = pcissue['title']
                if issue_title.startswith(key) or issue_title.endswith(key):
                    issue_title = key
                    break

        # store the vulnerability details
        if issue_title in issues_seen:
            issue_id = issues_seen[issue_title]['id']
            if issues_seen[issue_title]['fingerprint']:
                if fingerprint != issues_seen[issue_title]['fingerprint']:
                    logger.info('issue fingerprint changed, updating (' + issue_title +')')
                    details_seen = db_getrow('select description, remediation, severity, cvss, cvss3, cve from issues_seen\
                                              where id = %s', (issue_id,))
                    if not details_seen:
                        logerror(__name__, 'issue details not found: ' + str(issue_id) + '/' + issue_title)
                        return False

                    updated = False
                    for el in ['description', 'remediation', 'severity', 'cvss', 'cvss3', 'cve']:
                        if details_seen[el] != issue[el]:
                            logger.debug(el + ' has changed for ' + issue_title)
                            curs.execute('update issues_seen set ' + el + ' = %s where id = %s', (issue[el], issue_id))
                            updated = True

                    if updated:
                        curs.execute('update issues_seen set fingerprint = %s where id = %s', (fingerprint, issue_id))
                    else:
                        logerror(__name__, 'fingerprint changed but no differences found in ' + issue_title)
                        logger.debug(issues_seen[issue_title]['fingerprint'])
                        logger.debug(fingerprint)

        else:
            curs.execute('insert into issues_seen (title, name, description, remediation, severity, cvss, cvss3,\
                                                   cve, scanner, fingerprint)\
                          values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) returning id',
                          (issue_title, issue['name'], issue['description'], issue['remediation'], issue['severity'], issue['cvss'],
                           issue['cvss3'], issue['cve'], issue['scanner'], fingerprint))
            issue_id = curs.fetchone()[0]
            issues_seen.setdefault(issue_title, {'id': issue_id, 'fingerprint': fingerprint})

        # compile and store affected hosts and services
        svc_data = get_affected_services(riid, stats=True)
        host_count = len(svc_data.keys())
        svc_count = 0
        svc_stats = []
        # svc_data = {host_or_ip: {protocol: [port1, port2]}}
        for host in svc_data:
            host_hash = get_uniq_id(host)
            for protocol in svc_data[host]:
                svc_count += len(svc_data[host][protocol])
                for port in svc_data[host][protocol]:
                    port, service = port.split('#')
                    svc_stats.append([host_hash, protocol, port, service])

        curs.execute('insert into vuln_stats (eng_id, issue_id, exposure, host_count, service_count)\
                      values (%s, %s, %s, %s, %s) returning id',
                         (eng_id, issue_id, issue['exposure'], host_count, svc_count))
        vuln_id = curs.fetchone()[0]

        for row in svc_stats:
            row.insert(0, vuln_id)
            curs.execute('insert into service_stats (vuln_id, host_hash, protocol, port, service)\
                          values (%s, %s, %s, %s, %s)', tuple(row))

    curs.execute('update engagements set stats_exported = true where eid = %s', (eid,))
    try:
        conn.commit()
    except Exception as e:
        status['error'] = 'Failed to store stats'
        logerror(__name__, getframeinfo(currentframe()).lineno, status['error'])
        logger.error(e.pgerror)
        conn.close()

    conn.close()

    return status

def export_all():
    status = {'error': False}
    logging.basicConfig(filename='../logs/haxfarm.log',format='%(asctime)s %(filename)s [%(lineno)d] %(levelname)s:%(message)s',
                        level=logging.DEBUG)
    eng_list = db_getcol("select eid from engagements where eng_end < now() - interval '2 weeks'\
                                                            and isdummy is false and stats_exported is false")
    if eng_list:
        for eid in eng_list:
            logging.debug('exporting stats for eid ' + str(eid))
            status = export_stats(eid)
            if status['error']:
                break
    else:
        logging.debug('nothing to export')

    return status

def get_titlelist(term):
    ''' return a list of issue titles containing the search term '''
    today = date.today()
    exposure = request.args.get('exposure')
    if request.args['stat_from']:
        logger.debug('from is true: ' + repr(request.args['stat_from']))
        if request.args['stat_from'] != '':
            logger.debug('from has data')
    stat_from = request.args['stat_from'] if request.args['stat_from'] != '' else (today - timedelta(days=365)).strftime("%d/%m/%Y")
    stat_to = request.args['stat_to'] if request.args['stat_to'] != '' else today.strftime("%d/%m/%Y")
    searchstr = '%' + term.lower() + '%'
    logger.debug('getting autocomplete for titles using term: ' + term)

    param = []
    sql = 'select title from issues_seen where id in (select issue_id from vuln_stats where '
    if exposure != 'all':
        sql += 'exposure = %s and '
        param = [exposure]

    sql += 'eng_id in (select id from eng_stats where date between %s and %s)) and lower(title) like %s'
    param += [stat_from, stat_to, searchstr]

    result = db_getcol(sql, tuple(param))
    return result


