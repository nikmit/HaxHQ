import logging
import re
import copy
import difflib
import xhq.library
import psycopg2
from inspect import currentframe, getframeinfo
from datetime import date
from collections import namedtuple
from flask import Flask, request, session, flash
from markupsafe import escape
from docxtpl import RichText
from xhq.auth import authorise_access
from xhq.util import get_db, db_getrow, db_getcol, db_getdict, db_do, get_suffixed_number, is_ip, resolve, get_uniq_id, get_engagement_id, get_fingerprint, get_pg_update_sql, logerror, send_email, email_enabled
from xhq.pingcastle_config import pcastle_issues

logger = logging.getLogger(__name__)
logger.setLevel('INFO')
#logger.setLevel('DEBUG')

def get_csa_issue(iid, eid, data=None):
    user_id = session['user_id']
    # a data request needs all stuff outside the form - affected hosts, issue name and title, xtra_info
    if data:
        res = {**data, **{'active_engagement': eid, 'xtra_info': [], 'hidden_fields': ['CSRF Token']}}

        qry = db_getrow('select id, name, title, reference, benchmark, audit_file from csa_reporting where id = %s', (iid,))
        res['vuln'] = qry['data']

        qry = db_getdict('select service_name, policy_value, actual_value from csa_findings\
                          where id in (select finding_id from csa_servicevulns\
                                       where report_vuln_id = %s)\
                          order by service_name asc', (iid,))
        res['affected'] = qry['data']

        benchmark = res['vuln'].pop('benchmark')
        audit_file = res['vuln'].pop('audit_file')
        res['xtra_info'].append('Benchmark: ' + escape(benchmark.strip()))
        res['xtra_info'].append('Audit file: ' + escape(audit_file.strip()))

        policy_printed = False
        for audited_service in res['affected']:
            policy_value = audited_service.pop('policy_value')
            if not policy_printed and policy_value:
                res['xtra_info'].append('Expected policy value: ' + escape(policy_value.strip()))
                policy_printed = True
            actual_value = audited_service.pop('actual_value')
            if actual_value:
                res['xtra_info'].append('Actual value: ' + escape(actual_value.strip()))

        reference = res['vuln'].pop('reference')
        if reference:
            res['xtra_info'].append(escape(reference.strip()))

        return res
    # get issue details to populate form fields
    else:
        qry = db_getrow('select id, name, title, compliance, description, impact, remediation, rationale, ready,\
                                reference, audit_file, benchmark\
                         from csa_reporting where id = %s', (iid, ))
        issue = qry['data']

    suggestions = get_suggestions(issue['title']) if not issue['ready'] else None

    pending = {}
    if suggestions:
        fdata, pending = process_suggestions(issue, suggestions)
    else:
        logger.debug('issue marked ready or no suggestions for: ' + issue['title'])
        fdata = tuple( [issue['id'], issue['name'], issue['compliance'], issue['description'],
                        issue['rationale'], issue['impact'], issue['remediation'], issue['reference']] )


    FormData = namedtuple('FormData', 'iid, name, compliance, description, rationale, impact, remediation, reference')
    obj = FormData._make(fdata)
    return obj, pending

def get_vars(iid):
    logger.info('getting vars for user ' + session['nickname'])
    user_id = session['user_id']

    res = {'page': 'reporting', 'user': session['nickname'], 'user_groups': session['user_groups'], 'isadmin': session['isadmin'],
           'subtitle': 'Reporting', 'has_stats': authorise_access('stats'), 'success': True, 'email_enabled': email_enabled()}

    qry = db_getdict('select eid, org_name, test_type, summarised from engagements where active is true and user_id = %s', (user_id,))
    if qry['success']:
        if not qry['data']:
            logger.debug('no active engagement for reporting request')
            res['error'] = 'no active engagement'
            return res
        elif len(qry['data']) > 1:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'multiple engagements marked as activated!')
            res.setdefault('error', 'multiple engagements marked as activated')
            return res
        else:
            eng = qry['data'][0]
            logger.debug('got engagement data, eid: ' + str(eng['eid']))
            res['summarised'] = eng.pop('summarised')
            active_engagement = eng
            eng_type = active_engagement['test_type']
            res['eng_type'] = eng_type
    else:
        logger.error('query failed')

    if iid == 'all':
        # if issue id is 'all', return a summary listing of issues
        res = {**res, **{'hidden_fields': ['Import', 'File'], 'data': {}, 'active_engagement': active_engagement,
                         'rep_changed': False }}

        if eng_type == 'audit':
            qry = db_getdict("select id, title, compliance as severity, 'external' as exposure, ready, deleted, merged_with\
                              from csa_reporting\
                              where engagement_id = %s order by title asc", (active_engagement['eid'],))
            issues = qry['data']
            table = 'csa_reporting'
        else:
            qry = db_getdict('select id, title, severity, exposure, ready, autoupdated, ce_impact, deleted, merged_with\
                              from reporting\
                              where engagement_id = %s order by title asc', (active_engagement['eid'],))
            table = 'reporting'

            issues = []
            merged_deleted = []
            if qry['data']:
                for _issue in qry['data']:
                    if _issue['ready']:
                        res['rep_changed'] = True

                    if _issue['deleted'] or _issue['merged_with']:
                        merged_deleted.append(_issue)
                        res['rep_changed'] = True
                    else:
                        issues.append(_issue)

        if issues:
            if not res['summarised']:
                if res['rep_changed']:
                    flash('Summary has not been updated after adding or deleting scans', 'error')
                else:
                    # if no issues have been edited, merged or deleted, autosummarise on adding/removing scans
                    if summarise_findings():
                        return get_vars('all')

            for issue in issues:
                severity = issue['severity']
                exposure = issue['exposure']
                del issue['severity']
                del issue['exposure']
                if exposure in res['data']:
                    res['data'][exposure].setdefault(severity, []).append(issue)
                else:
                    res['data'].setdefault(exposure, {severity: []})
                    res['data'][exposure][severity].append(issue)
        else:
            if not res['summarised'] and summarise_findings():
                return get_vars('all')

    else:
        # loading specific issue, authorise
        eid, test_type = get_engagement_id(test_type=True)
        reporting_table = 'csa_reporting' if test_type == 'audit' else 'reporting'
        qry = db_getcol('select id from ' + reporting_table + ' where id = %s and engagement_id = %s', (iid, eid))
        if qry['success']:
            if not qry['data']:
                logger.warn('refusing access to issue not owned by user ' + str(user_id))
                flash('Issue not found in this engagement. If this is a persistent error, please contact support', 'error')
                res['success'] = False
                return res
        else:
            logger.error('query failed')

        # get issue metadata - the texts for the issue edit form are retrieved separately at get_issue
        if active_engagement['test_type'] == 'audit':
            return get_csa_issue(iid, active_engagement, data=res)

        # if displaying a specific issue get detailed info
        res = {**res, **{'active_engagement': active_engagement, 'affected': [], 'vuln': [], 'xtra_info': [],
                         'subtitle': 'Edit finding', 'hidden_fields': ['CSRF Token']}}
        # if we start using 'see_also' and 'notes', this more complex query can be used again
        #res['vuln'] = db_getrow('select reporting.id, reporting.title, coalesce(reporting.name, reporting.title) as name,\
        #                                reporting.severity, reporting.proof, see_also, notes, reporting.cvss,\
        #                                reporting.cvss3, reporting.cve\
        #                         from reporting\
        #                           left join servicevulns on reporting.id = servicevulns.report_vuln_id\
        #                           left join services on services.id = servicevulns.service_id\
        #                           left join findings on findings.service_id = services.id\
        #                         where reporting.id = %s limit 1', (iid,))

        qry = db_getrow('select id, title, coalesce(name, title) as name, severity, proof, cvss, cvss3, cvss3_vector, cve, exposure\
                         from reporting where id = %s', (iid,))
        if qry['success']:
            res['vuln'] = qry['data']
            if not res['vuln']:
                logerror(__name__, getframeinfo(currentframe()).lineno,
                         'No issue found in the reporting table with this id: ' + str(iid))
                res['success'] = False
                return res

        res['libentry_exists'] = False
        qry = db_getdict('select id, exposure from library where title = %s', (res['vuln']['title'],))
        if qry['success']:
            if qry['data']:
                for entry in qry['data']:
                    if entry['exposure'] == res['vuln']['exposure']:
                        res['libentry_exists'] = 'match'
                        break
                    else:
                        res['libentry_exists'] = entry['exposure']

                if res['libentry_exists']:
                    logger.info('library entry exists: ' + repr(res['libentry_exists']))
        else:
            logger.error('query failed')

        res['vuln'].setdefault('mergeables', suggest_merge_delete(iid, yesno=True))

        #TODO using max(virthost) to pick up a random fqdn for an affected host is not good, needs to use webappurl
        qry = db_getdict("select coalesce(ipv4, ipv6) as ip, coalesce(vhost, max(virthost)) as vhost,\
                                 protocol, port, services.id as sid, hosts.id as hid\
                          from services\
                            join hosts on services.host_id = hosts.id\
                            join findings on service_id = services.id\
                            left join http_virthost on hosts.id = http_virthost.host_id\
                          where findings.id in (select finding_id from servicevulns\
                                                where report_vuln_id in (select id from reporting\
                                                                         where id = %s or merged_with = %s))\
                          group by ip, vhost, protocol, port, sid, hid\
                          order by ip asc, vhost asc", (iid, iid))

        if qry['success']:
            res['affected'] = qry['data']
            if not res['affected']:
                logerror(__name__, getframeinfo(currentframe()).lineno, 'finding has no affected hosts')
                logger.error('finding has no affected hosts: ' + str(eid) + '/' + str(iid))
                logger.error(repr(res['affected']))
                flash('Finding has no affected hosts (after deleting a scan please summarise findings)', 'error')
                res['success'] = False
                return res
        else:
            logger.error('query failed')

        qry = db_getdict('select coalesce(ipv4, ipv6) as ip, port, plugin_output, see_also\
                          from findings\
                            join issues_seen on issue_id = issues_seen.id\
                            left join services on service_id = services.id\
                            left join hosts on host_id = hosts.id\
                          where service_id in (select service_id from servicevulns where report_vuln_id = %s)\
                            and title = %s', (iid, res['vuln']['title']))

        xtra_data = qry['data']
        if xtra_data:
            logger.debug('plugin ouput present, compiling')

            # reference links are always the same for all hosts affected by the same issue, get the first entry
            see_also = xtra_data[0]['see_also']
            if see_also:
                res['xtra_info'].append('See also: ' + see_also + '\n')

            # if the same extra data applies to all hosts, don't list it by ip
            po_set = set([row['plugin_output'] for row in xtra_data])
            if len(po_set) > 1:
                try:
                    res['xtra_info'] += [row['ip'] + ':' + str(row['port']) + ' - ' + escape(row['plugin_output']) for row in xtra_data if row['plugin_output']]
                except Exception as e:
                    logerror(__name__, getframeinfo(currentframe()).lineno, 'error parsing plugin_output')
                    logger.error(repr(xtra_data))
            else:
                if xtra_data[0]['plugin_output']:
                    res['xtra_info'].append(escape(xtra_data[0]['plugin_output']))

    return res

def summarise_csa(eid):
    # a straight copy from findings
    # currently only using nessus so scanner is hardcoded
    qry = db_getdict('select id, service_id, title, description, rationale, solution as remediation, impact, compliance,\
                             reference, audit_level, control_set, benchmark, audit_file\
                      from csa_findings where engagement_id = %s', (eid,))
    if qry['success']:
        findings = qry['data']
    else:
        findings = {}
        logger.error('query failed')
    # summarise by title
    summary = {}
    for f in findings:
        title = f['title']
        sid = f.pop('service_id')
        fid = f.pop('id')
        if title in summary:
            summary[title]['idlist'].append({'sid': sid, 'fid': fid})
        else:
            summary[title] = {**f, **{'idlist': [{'sid': sid, 'fid': fid}]}}

    logger.debug('starting db save')
    conn = get_db()
    curs = conn.cursor()
    for title in summary:
        idlist = summary[title].pop('idlist')
        _issue = summary[title]
        _issue.setdefault('engagement_id', eid)
        _issue.setdefault('name', title)
        _issue.setdefault('scanner', 'nessus')
        columns = _issue.keys()
        values = _issue.values()

        sql = 'insert into csa_reporting (' + ', '.join(columns)  + ') values (' + '%s, '*(len(columns) - 1) + '%s) returning id'
        try:
            curs.execute(sql, (tuple(values)))
            rid = curs.fetchone()[0]
        except conn.Error as e:
            logger.error('database error: ' + e.pgerror)
            logerror(__name__, getframeinfo(currentframe()).lineno, 'csa_reporting insert failed')
            conn.close()
            return False

        for _id in idlist:
            sid = _id['sid']
            fid = _id['fid']
            try:
                curs.execute('insert into csa_servicevulns (service_id, report_vuln_id, finding_id)\
                                          values (%s, %s, %s)', (sid, rid, fid))
            except conn.Error as e:
                logger.error('database error: ' + e.pgerror)
                logerror(__name__, getframeinfo(currentframe()).lineno, 'query failed')
                conn.close()
                return False

    curs.execute('update engagements set summarised = true where eid = %s', (eid,))
    conn.commit()
    conn.close()
    logger.debug('finished db save')

    return True

def summarise_findings():
    eid, test_type = get_engagement_id(test_type=True)
    clear_summary()

    if test_type == 'audit':
        logger.debug('summarising csa data')
        return summarise_csa(eid)

    logger.debug('summarising pentest data')
    qry = db_getdict('select findings.id, service_id, title, description, remediation, proof, cvss, cvss3,\
                             cvss3_vector, cvss_vector, cve,\
                             impact, exploit_available, exploitability_ease, severity, see_also, external, scanner\
                      from findings\
                        join issues_seen on issue_id = issues_seen.id\
                      where engagement_id = %s', (eid,))
    if qry['success']:
        findings = qry['data']
    else:
        findings = {}
        logger.error('query failed')

    summary = {}
    # compile a list of unique findings with the list of services they affect and the exposure type and any proof per service
    for f in findings:
        title = f['title']
        exposure = 'external' if f['external'] else 'internal'
        scanner = f['scanner']
        if scanner == 'pingcastle':
            exposure = 'adreview'
            for pcissue in pcastle_issues:
                key = pcissue['title']
                if title.startswith(key) or title.endswith(key):
                    title = key
                    break

        service_id = f['service_id']
        # for pingcastle issues report only once per title, summarising per service creates duplicate details/info entries
        if title in summary:
            # services should be unique per finding
            # if any is seen both inside and outside, the outside entry clobbers the inside one during scan import
            # titles are expected to be unique per scanner.
            # With multiple entries of a type at different severities, scanner importers should keep the highest severity
            summary[title]['services'][service_id] = {'exposure': exposure, 'proof': f['proof'], 'finding_id': f['id']}
            # log any title clashes
            if 'scanner' in summary[title]:
                if summary[title]['scanner'] != scanner:
                    logger.warn('title clash: "' + title + '" is reported by both ' + scanner + ' and ' + summary[title]['scanner'])
                    summary[title]['scanner'] = scanner
            else:
                logerror(__name__, getframeinfo(currentframe()).lineno, 'summary entry with missing scanner key')
                logger.error(repr(summary[title]))
        else:
            summary[title] = {'services': {service_id: {'exposure': exposure, 'proof': f['proof'], 'finding_id': f['id']}},
                              'scanner': scanner}

            # if seeing this finding for the first time, clean up and then store the non-service-specific data
            if scanner == 'pingcastle':
                logger.debug('adding name for pingcastle finding')
                f.setdefault('name', title)
            # remove columns which are unneeded at this point
            for key in ['service_id', 'proof']:
                del f[key]

            summary[title]['params'] = f

    fields = ['engagement_id', 'title', 'severity', 'description', 'exploitability',
              'impact', 'remediation', 'cvss', 'cvss3', 'cvss3_vector', 'cvss_vector', 'cve', 'name', 'scanner']
    # prep data for database insert
    logger.debug('starting db save')
    conn = get_db()
    curs = conn.cursor()
    for title in summary:
        scanner = summary[title]['scanner']
        entry = {}
        vals = [eid, title, scanner]
        cols = ['engagement_id', 'title', 'scanner']
        for field in fields:
            #logger.debug('checking out ' + field)
            if field in cols:
                continue
            elif field == 'exploitability':
                exploitability = summary[title]['params']['exploitability_ease']
                if exploitability:
                    cols.append('exploitability')
                    vals.append(exploitability)
            else:
                if field in summary[title]['params'] and summary[title]['params'][field] is not None:
                    vals.append(summary[title]['params'][field])
                    cols.append(field)
                else:
                    logger.debug('no ' + field + ' field in ' + title)
                    #logger.debug(repr(summary[title]['params']))

        # handle service-specific values
        # need 2 separate entries for a vuln which is external for some services and internal only for others
        for service_id in summary[title]['services']:
            exposure = summary[title]['services'][service_id]['exposure']
            proof = summary[title]['services'][service_id]['proof']
            finding_id = summary[title]['services'][service_id]['finding_id']
            if exposure in entry:
                entry[exposure]['services'].setdefault(service_id, []).append(finding_id)
                if proof:
                    logger.debug(scanner + ' proof seen')
                    if scanner == 'pingcastle':
                        if proof not in entry[exposure]['proofs']:
                            logger.debug('fresh proof, adding: ' + repr(proof))
                            entry[exposure]['proofs'].append(proof)
                        else:
                            logger.debug('proof already present, skipping')
                    else:
                        entry[exposure]['proofs'].append(proof)
            else:
                entry[exposure] = {'services': {service_id: []}, 'proofs': []}
                entry[exposure]['services'][service_id].append(finding_id)
                if proof:
                    logger.debug(scanner + ' proof seen')
                    if scanner == 'pingcastle':
                        if proof not in entry[exposure]['proofs']:
                            logger.debug('fresh proof, adding: ' + repr(proof))
                            entry[exposure]['proofs'].append(proof)
                    else:
                        entry[exposure]['proofs'].append(proof)

        #logger.debug('got ' + str(len(cols)) + ' cols and ' + str(len(vals)) + ' values')

        for exposure in entry:
            # make a copy of cols and vals so it can be modified per exposure
            columns = cols[:]
            values = vals[:]

            #logger.debug('got ' + str(len(columns)) + ' cols and ' + str(len(values)) + ' values')
            if entry[exposure]['proofs']:
                values.append('\n'.join(entry[exposure]['proofs']))
                columns.append('proof')

            columns.append('exposure')
            values.append(exposure)

            sql = 'insert into reporting (' + ', '.join(columns)  + ') values (' + '%s, '*(len(columns) - 1) + '%s) returning id'
            logger.debug('inserting: ' + sql)
            logger.debug('values: ' + repr(values))
            curs.execute(sql, tuple(values))
            rid = curs.fetchone()[0]

            for service_id in entry[exposure]['services']:
                for fid in entry[exposure]['services'][service_id]:
                    #logger.debug('updating service ' + str(service_id) + ': report_vuln_id/finding_id ' + str(rid)+ '/' + str(fid))
                    curs.execute('insert into servicevulns (report_vuln_id, service_id, finding_id) values (%s, %s, %s)',
                                                (rid, service_id, fid))

    curs.execute('update engagements set summarised = true where eid = %s', (eid,))
    conn.commit()
    conn.close()
    logger.debug('finished db save')

    return True

def autoupdate_issues():
    if session:
        user_id = session['user_id']
    else:
        # if this is run manually from a python shell there's no session
        #user_id = 1
        logerror(__name__, getframeinfo(currentframe()).lineno, 'could not find session, abandon autoupdate')
        return False

    eid, test_type = get_engagement_id(test_type=True)

    if test_type == 'audit':
        sql = 'select id, title, name, description, rationale, remediation, compliance, impact, reference\
               from csa_reporting\
               where engagement_id = %s and ready is false and autoupdated is false and deleted is false and merged_with is null'
        fields = ['name', 'description', 'rationale', 'remediation', 'compliance', 'impact', 'reference']
    else:
        sql = 'select id as iid, title, name, description, discoverability, exploitability, remediation, severity, impact, exposure\
               from reporting\
               where engagement_id = %s and ready is false and autoupdated is false and deleted is false and merged_with is null'
        fields = ['name', 'description', 'discoverability', 'exploitability', 'remediation', 'severity', 'impact', 'exposure']

    qry = db_getdict(sql, (eid,))
    if qry['success']:
        if qry['data']:
            rep_items = qry['data']
        else:
            flash('All issues already updated or marked ready', 'info')
            return True
    else:
        logger.error('query failed')

    for item in rep_items:
        suggestions = xhq.library.get_suggestions(item['title'], exposure=item['exposure'], autoupdate=True)
        if suggestions:
            updated_item, metadata = suggestions
            if updated_item:
                updated_item['iid'] = item['iid']
                updated_item['cmd'] = 'saverep'
                logger.debug(item['title'] + ' - scanner changes: ' + str(len(metadata['scanner_changes']) > 0))
                if not metadata['scanner_changes']:
                    updated_item.setdefault('autoupdated', True)
                    #for key in fields:
                    #    # only autoupdate if the library entry is complete with all needed data
                    #    if not updated_item[key]:
                    #        if 'severity' not in fields or int(updated_item['severity']) > 2:
                    #            logger.debug(key + ' missing from data, abandoning autoupdate')
                    #            break
                    #        elif key in ['discoverability', 'exploitability', 'impact']:
                    #            continue
                    #else:
                    logger.debug('saving autoupdates for: ' + item['title'])
                    status = save_issue(data = updated_item, eid = eid, test_type = test_type)

                    if status['error']:
                        flash(status['error'], 'error')
                        return False
                else:
                    logger.debug('scanner texts changed, ignoring issue during autoupdate')
            else:
                logger.debug('no library entry for ' + item['title'])
        else:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'unexpected return value from library.get_suggestions')
            logger.debug(repr(suggestions))

    return True

def suggest_merge_delete(iid, yesno=False):
    # look at other e.g. internal issues with similar titles and return a list of suggestions to merge or delete
    # issues with similar names and same severity are candidates for merging
    # issues with similar names but differing severities are candidates if they affect the same hosts
    # where the lower severity issue affects same hosts plus new ones, the repeat hosts can be removed from the affected list
    qry = db_getrow('select id as iid, engagement_id as eid, name, title, severity::text, exposure\
                     from reporting where id = %s', (iid,))

    if qry['success']:
        issue = qry['data']
    else:
        logger.error('query failed')
        return False

    issue['affected_count'] = 0
    affected = get_affected_services(iid, reportby='IP address')
    for ip in affected:
        string = ip + ':'
        for proto in affected[ip]:
            issue['affected_count'] += len(affected[ip][proto])
            string += ' ' + proto + '/' + ','.join(affected[ip][proto])

        issue.setdefault('affected', []).append(string)

    title = copy.copy(issue['title'])
    title_words = title.lower().split(' ')
    # list of first words which should not trigger suggestions on their own, check at least the next one too
    common_start_words = ['the', 'web', 'ssl', 'microsoft', 'hp', 'cisco', 'unsupported', 'missing', 'presence', 'number', 'ssh', 'adobe']
    ignore_words = ['ssl certificate', 'ssl self-signed', 'ssh weak', 'web server', 'missing or', 'number of', 'presence of']
    search_term = title_words[0] if title_words[0] not in common_start_words else ' '.join(title_words[0:2])

    if search_term in ignore_words:
        return False

    logger.debug('using search term ' + search_term)
    search_term += ' %'

    qry = db_getdict('select id, name, title, severity::text from reporting\
                      where engagement_id = %s and lower(title) like %s and id != %s and severity <= %s\
                        and merged_with is null and deleted is false and exposure = %s\
                      order by severity desc, title',
                                     (issue['eid'], search_term, iid, issue['severity'], issue['exposure']))
    if qry['success']:
        merge_candidates = qry['data']
    else:
        logger.error('query failed')
        return False

    if yesno:
        #logger.debug(repr(merge_candidates))
        return True if merge_candidates else False

    #severitymap = {'0': 'Info', '1': 'Low', '2': 'Medium', '3': 'High', '4': 'Crit'}
    # compile a dict of issues and affected hosts
    candata = []
    for candidate in merge_candidates:
        #a[ip][proto] = [portlist]
        candidate_affected = get_affected_services(candidate['id'], reportby='IP address')
        missing = []    # services not affected by the original issue under revew
        repeat = []     # services affected by both issues
        for ip in candidate_affected:
            if ip in affected:
                for proto in candidate_affected[ip]:
                    if proto in affected[ip]:
                        for port in candidate_affected[ip][proto]:
                            if port in affected[ip][proto]:
                                repeat.append(proto + ' ' + ip + ':' + str(port))
                            else:
                                missing.append(proto + ' ' + ip + ':' + str(port))
                    else:
                        for port in candidate_affected[ip][proto]:
                            missing.append(proto + ' ' + ip + ':' + str(port))
            else:
                for proto in candidate_affected[ip]:
                    for port in candidate_affected[ip][proto]:
                        missing.append(proto + ' ' + ip + ':' + str(port))

        candata.append({'id':candidate['id'], 'title': candidate['title'], 'severity': candidate['severity'],
                        'missing': missing, 'repeat': repeat})

    res = {'merge_candidates': [], 'cleanup_list': [], 'vuln': issue, 'user_groups': session['user_groups'],
           'has_stats': authorise_access('stats'), 'page': 'reporting', 'user': session['nickname'], 'subtitle': 'Merge findings',
           'isadmin': session['isadmin'] }
    # create a set of issues which affect the exact same services and may therefore be mergeable
    # create a set of hosts which are present in similar issues affecting them and other hosts,
    # and should likely be removed from any lower severity affected lists
    for candidate in candata:
        logger.debug('checking if mergeable: ' + candidate['title'])
        # if this merge candidate affects services not affected by the original issue
        if candidate['missing']:
            #logger.debug('issue affects additional services: ' + repr(candidate['missing']))
            if int(candidate['severity']) == int(issue['severity']):
                # if both issues at same severity, they may still be mergeable
                logger.debug('appending same severity issue (missing services) for merging')
                res['merge_candidates'].append(candidate)
            elif int(candidate['severity']) < int(issue['severity']):
                if candidate['repeat']:
                    # if the candidate is of lower severity, but contains services affected by the higher severity issue
                    # suggest removing services already flagged with a more serious issue
                    res['cleanup_list'].append(candidate)
                    res['merge_candidates'].append(candidate)
                    logger.debug('appending candidate for cleaning from lower severity issue')
                else:
                    res['merge_candidates'].append(candidate)
                    logger.debug('no affected list clean up suggestions: ' + candidate['title'])
            else:
                logger.warning('higher severity issue seen, how?')
                logger.debug(str(candidate['severity']) + ' <> ' + str(issue['severity']))
        else:
            # if all services affected by the candidate are also affected by the currently reviewed issue
            # then it is a likely merge candidate
            res['merge_candidates'].append(candidate)
            logger.debug('candidate affects same hosts as original issue (or a subset of them), appending for merge')

    #logger.debug(repr(res))
    return res

def get_issue(iid, reloadlib=False):
    # gets issue details and passes the object to populate issueedit form
    # other related vars, e.g. affected hosts are retrieved in get_vars
    # get title so it can be used for suggestion search
    user_id = session['user_id']
    engagement, test_type = get_engagement_id(test_type=True)
    if test_type == 'audit':
        return get_csa_issue(iid, engagement['eid'])

    # define default values for issue, changes etc
    metadata = {}
    # if cvss3 data exists, use it; don't use cvss v2 score, only v2 vector
    qry = db_getrow('select id as iid, title, coalesce(name, title) as name, exposure, severity::text, cvss3,\
                            coalesce(cvss3_vector, cvss_vector) as vector, description, proof, discoverability, exploitability,\
                            impact, remediation, ready, autoupdated, details\
                     from reporting where id = %s', (iid,))
    if qry['success']:
        issue = qry['data']
    else:
        logger.error('query failed')
        return False
    # extract details info from reporting table
    if issue['proof']:
        details = issue['proof']

        if issue['details'] and issue['details'] != issue['proof']:
            details = issue['proof'] + '\n\n' + issue['details']
    else:
        details = issue['details']

    # try to get library suggestions if needed
    if reloadlib or not (issue['ready'] or issue['autoupdated']):
        suggestions = xhq.library.get_suggestions(issue['title'], exposure=issue['exposure'])
        if suggestions:
            # if library entry available, override default data
            library_issue, metadata = suggestions
            issue = issue | library_issue
    else:
        logger.debug('issue marked ready or no suggestions for: ' + issue['title'])

    #logger.debug('#### ' + repr((issue['cvss3'], issue['vector'])))
    # compile a named tuble for passing to WTForms
    fdata = tuple( [issue['iid'], issue['name'], issue['exposure'], issue['severity'], issue['cvss3'], issue['vector'],
                    issue['description'], details, issue['discoverability'], issue['exploitability'], issue['impact'],
                    issue['remediation']] )
    # adding v2/3 vector data into cvss3_vector as the calc is backwards compatible
    # but anything saved there should be v3
    FormData = namedtuple('FormData', 'iid, name, exposure, severity, cvss3, cvss3_vector, description, details, discoverability, exploitability, impact, remediation')
    obj = FormData._make(fdata)
    return obj, metadata

def save_libissue(scannerdata, issue, user_id, issue_libid):
    #TODO OBSOLETE - REMOVE ONCE CSA HANDLING IS DONE
    # adds/updates the library stored parameters for the submitted issue
    # scannerdata contains the issue data before editing or importing library suggestions
    # issue contains the text as sumbitted in the form after editing
    # get any existing texts for this issue from library

    if scannerdata and 'severity' in scannerdata:
        if int(scannerdata['severity']) == int(issue['severity']):
            severity_mod = 0
        else:
            severity_mod = int(issue['severity']) - int(scannerdata['severity'])
    else:
        severity_mod = 0

    # loop through the fields and look for changes in data
    for fld in ['name', 'severity', 'cvss3', 'cvss3_vector', 'description', 'discoverability', 'exploitability',
                'impact', 'remediation', 'rationale', 'reference']:
        # if something other than an empty string was submitted for the field
        if fld in issue and issue[fld]:
            # should be able to add text to lib even if there is none from the scanner?
            if fld not in scannerdata:
                logger.info('field missing from form data: ' + fld)
                logger.debug('assuming manually added issue, adding token scanner data')
                # scanner data is used to create the ignore text,
                # which is used to force an update to library if the scanner has updated a text
                # for manually added issues scanner data is not needed, adding a symbolic value cause the code expects it ...
                scannerdata.setdefault(fld, 'asdf')
            # store the submitted one
            if fld in ['description', 'remediation', 'rationale', 'impact', 'reference']:
                # delete old text for this issue and this user
                db_do('delete from issue_' + fld + ' where issue_id = %s and user_id = %s', (issue_libid, user_id))
                # insert the new text
                logger.debug('saving issue ' + fld + ' to library, issue id: ' + str(issue_libid))
                db_do('insert into issue_' + fld + ' (issue_id, text, prefer, user_id) values (%s, %s, %s, %s)',
                            (issue_libid, issue[fld], 'true', user_id))
                db_do('insert into issue_' + fld + ' (issue_id, text, ignore, user_id) values (%s, %s, %s, %s)',
                            (issue_libid, scannerdata[fld], 'true', user_id))
            elif fld in ['discoverability', 'exploitability']:
                # delete old text for this issue and this user
                db_do('delete from issue_' + fld + ' where issue_id = %s and user_id = %s', (issue_libid, user_id))
                # insert tha new text
                logger.debug('adding ' + fld + ' text to library')
                db_do('insert into issue_' + fld + ' (issue_id, text, user_id) values (%s, %s, %s)',
                            (issue_libid, issue[fld], user_id))

            elif fld == 'severity':
                if severity_mod:
                    logger.debug('severity modified, updating library (scanner: ' + str(scannerdata['severity']) + ', submitted: ' + str(issue['severity']))
                    db_do('update issues set (severity, severity_mod) = (%s, %s) where id = %s',
                                    (issue['severity'], severity_mod, issue_libid))
            elif fld == 'name':
                logger.debug('updating issue name')
                db_do('update issues set name = %s where id = %s', (issue['name'], issue_libid))
            else:
                logger.debug('adding new ' + fld + ' text to library')
                db_do('insert into issue_' + fld + ' (issue_id, text, user_id) values (%s, %s, %s)',
                                 (issue_libid, issue[fld], user_id))
        else:
            logger.debug('no ' + fld + ' data, nothing to update with')

def update_library_csa(issue):
    #TODO OBSOLETE - REMOVE ONCE CSA HANDLING IS DONE
    user_id = session['user_id']
    title = issue['title'].strip()

    name = issue['name'].strip()

    if not title:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'no title value submitted')
        logger.debug(name)
        title = name

    logger.debug('updating library csa entry for ' + title)
    # get the scanner texts from reporting (title is not editable in form, stays same)
    # can be text manually entered when creating a custom issue
    qry = db_getrow('select name, description, rationale, impact,\
                             remediation, compliance, reference from csa_reporting where id = %s', (issue['iid'],))
    if qry['success']:
        scannerdata = qry['data']
    else:
        logger.error('query failed')
        return False

    compliance = scannerdata['compliance']
    # only update based on titles, not names else things get messy
    qry = db_getrow('select id from issues where title = %s', (title,))
    if qry['success']:
        bytitle = qry['data']
    else:
        logger.error('query failed')
        return False

    if bytitle:
        # if a library entry exists
        issue_libid = bytitle['id']
        logger.debug('found existing issue in library with id ' + str(issue_libid))
        # update / add issue texts
        save_libissue(scannerdata, issue, user_id, issue_libid)
    else:
        # if issue is not in library yet, add it
        logger.debug('creating new issue in library')
        values = (name, title, compliance)
        #logger.debug(repr(values))
        qry = db_do('insert into issues (name, title, compliance) values (%s, %s, %s) returning id', values)
        if qry['success']:
            # update / add issue texts
            logger.debug('issue saved, adding issue texts')
            save_libissue(scannerdata, issue, user_id, qry['data'])
        else:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to create new issue')
            return False

    return True

def update_library(issue):
    #TODO OBSOLETE - REMOVE ONCE CSA HANDLING IS DONE
    # checks if issue with given title exists and creates it if not
    # then passes to save_libissue to store all the texts for it
    #
    # title is what the issue is called by the scanner
    # name is what we put in reports - can be same as title
    # titles have to be unique in db
    # there should be one 'ignored' and 'preferred' pair per issue per user_id
    # original scanner texts that are replaced need to be stored as ignored to avoid blindly overwriting any future change in scanner text
    user_id = session['user_id']
    title = issue['title'].strip()
    name = issue['name'].strip()

    if not title:
        # manually created issues have no title, better add it here than in javascript
        title = name

    searchtitle = title
    for pcissue in pcastle_issues:
        key = pcissue['title']
        if title.startswith(key):
            # pingcastle titles contain engagement specific info in the end
            logger.debug('trimming pingcastle title before storing in library: ' + title)
            title = key
            searchtitle = title + '%'
            break
        elif title.endswith(key):
            logger.debug('trimming pingcastle title before storing in library: ' + title)
            title = key
            searchtitle = '%' + title
            break

    logger.debug('updating library entry for ' + title)
    # get the scanner texts from reporting (title is not editable in form, stays same)
    # can be text manually entered when creating a custom issue

    # get description, remediation, severity directly from findings table.
    qry = db_getrow('select description, solution as remediation, severity\
                     from findings join issues_seen on issue_id = issues_seen.id\
                     where service_id in (select service_id from servicevulns where report_vuln_id = %s)\
                        and title like %s', (issue['iid'], searchtitle))
    scannerdata = qry['data']
    qry = db_getrow('select name, discoverability, exploitability, impact from reporting where id = %s', (issue['iid'],))
    reportdata = qry['data']

    if scannerdata and reportdata:
        scannerdata = {**scannerdata, **reportdata}
    elif scannerdata:
        pass
    elif reportdata:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'could not load scannerdata')
        return False
    else:
        scannerdata = {}

    severity = scannerdata['severity'] if scannerdata else None
    # only update based on titles, not names else things get messy
    # pingcastle titles are already standardised here so no need to use searchtitle
    qry = db_getrow('select id from issues where title = %s', (title,))
    bytitle = qry['data']
    if bytitle:
        # if a library entry exists
        issue_libid = bytitle['id']
        logger.debug('found existing issue in library with id ' + str(issue_libid))
        # update / add issue texts
        save_libissue(scannerdata, issue, user_id, issue_libid)
    else:
        # if issue is not in library yet, add it
        logger.debug('creating new issue in library')
        if severity:
            severity_mod = 0 if severity == issue['severity'] else int(issue['severity']) - int(severity)
        else:
            severity_mod = 0

        values = (name, title, issue['severity'], severity_mod)
        #logger.debug(repr(values))
        qry = db_do('insert into issues (name, title, severity, severity_mod) values (%s, %s, %s, %s) returning id', values)
        if qry['success']:
            issue_libid = qry['data']
            # update / add issue texts
            logger.debug('issue saved, adding issue texts')
            save_libissue(scannerdata, issue, user_id, issue_libid)
        else:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to create new issue')
            return False

    return True

def update_issue(issue):
    # simply save form data to reporting table and mark ready
    iid = issue['iid']
    logger.debug('updating report issue ' + str(iid))
    update_cols = []
    update_vals = []
    for col in ['name', 'cvss3', 'cvss3_vector', 'severity', 'description', 'details', 'discoverability', 'exploitability',
                'impact', 'remediation', 'autoupdated']:
        # exclude DIEs for low severity issues
        if col in issue and issue[col]:
            logger.debug('adding col ' + col + ' and value ' + str(issue[col]))
            update_cols.append(col)
            update_vals.append(issue[col])
        else:
            # DIEs missing for lower severities
            logger.info('could not find ' + col + ' in submitted data')

    if update_cols:
        # set the ready flag only if submitted through form (no data_complete)
        # or if autoupdate contains data for all form fields (data_complete = True)
        if 'autoupdated' not in issue or not issue['autoupdated']:
            update_cols.append('ready')
            update_vals.append('true')
        # add iid to values, used for the where condition so no col for it
        update_vals.append(iid)
        sql = get_pg_update_sql('reporting', update_cols, 'where id = %s')
        db_do(sql, tuple(update_vals))
    else:
        logger.debug('no changes, nothing to do for iid ' + str(iid))

    if 'autoupdated' not in issue or not issue['autoupdated']:
        # dont clean during autoupdates yet. If enabled will need to deal with potential issue set change as issues are deleted
        if issue['title'].strip() in ['SSL Self-Signed Certificate', 'SSL Certificate Expiry', 'SSL Certificate with Wrong Hostname']:
            logger.debug('cleaning cert hosts')
            clean_cert_hosts(issue)

    return True

def update_csa_issue(issue):
    # simply save form data to reporting table and mark ready
    iid = issue['iid'] if 'iid' in issue else issue['id']
    logger.debug('updating report issue ' + str(iid))
    update_cols = []
    update_vals = []
    for col in ['name', 'description', 'rationale', 'reference', 'impact', 'remediation', 'compliance']:
        if col in issue and issue[col]:
            logger.debug('adding col ' + col + ' and value ' + str(issue[col]))
            update_cols.append(col)
            update_vals.append(issue[col])
        else:
            # DIEs missing for lower severities
            logger.info('could not find ' + col + ' in submitted data')

    if update_cols:
        # set the ready flag only if submitted through form (no data_complete)
        # or if autoupdate contains data for all form fields (data_complete = True)
        if 'data_complete' not in issue or issue['data_complete']:
            update_cols.append('ready')
            update_vals.append('true')

        # add iid to values, used for the where condition so no col for it
        update_vals.append(iid)
        # placeholders need to be one less than len update_vals to allow for iid in the where condition
        if len(update_cols) > 1:
            sql = 'update csa_reporting set (' + ', '.join(update_cols) + ') = (' + '%s, '*(len(update_vals) - 2) + '%s) where id = %s'
        else:
            sql = 'update csa_reporting set ' + update_cols[0] + ' = %s where id = %s'

        db_do(sql, tuple(update_vals))
    else:
        logger.debug('no changes, nothing to do for iid ' + str(iid))



def clean_cert_hosts(issue):
    user_id = session['user_id']
    ''' removes hosts affected by these issues in order from all remaining issues of same or lower severity (if any):
     'SSL Certificate Expiry'
     'SSL Self-Signed Certificate'
     'SSL Certificate with Wrong Hostname'
     'SSL Certificate Cannot Be Trusted' '''
    logger.debug('cleaning affected hosts lists for cert issues')
    titles = ['SSL Certificate Expiry', 'SSL Self-Signed Certificate',
              'SSL Certificate with Wrong Hostname', 'SSL Certificate Cannot Be Trusted']

    title = issue['title'].strip()
    report_iid = issue['iid']
    eid = get_engagement_id()

    start = False
    for title2clean in titles:
        if title == title2clean:
            start = True
            logger.debug('found')
            continue

        if start:
            logger.debug('cleaning hosts from ' + title2clean)
            db_do('delete from servicevulns\
                   where service_id in (select service_id from servicevulns\
                                        where report_vuln_id = %s)\
                    and report_vuln_id = (select id from reporting\
                                          where title = %s\
                                            and engagement_id = %s\
                                            and exposure = (select exposure from reporting\
                                                            where id = %s))', (report_iid, title2clean, eid, report_iid))

            logger.debug(repr((title2clean, eid, report_iid)))
            qry = db_getcol('select count(id) from servicevulns\
                             where report_vuln_id = (select id from reporting\
                                                     where title = %s\
                                                        and engagement_id = %s\
                                                        and exposure = (select exposure from reporting\
                                                                        where id = %s))',
                                          (title2clean, eid, report_iid))
            remaining_affected = qry['data']
            logger.debug('cleaned hosts from ' + title2clean + ', remaining ' + str(remaining_affected) + ' services')
            if not remaining_affected:
                logger.debug(repr((title2clean, eid, report_iid)))
                logger.debug('no affected hosts remaining after cleaning issue, removing issue')
                try:
                    qry = db_do('delete from reporting\
                                 where title = %s\
                                    and engagement_id = %s\
                                    and exposure = (select exposure from reporting\
                                                    where id = %s) returning id', (title2clean, eid, report_iid))
                    deleted_id = qry['data']
                    logger.debug('deleted issue ' + str(deleted_id))
                except Exception as e:
                    # no check is done whether an issue with the title exists.
                    # any fetch errors should be trapped in db_do though
                    logger.error(e.pgerror)
                    logerror(__name__, getframeinfo(currentframe()).lineno,
                             'failed to delete ssl issue after removing all affected hosts')
        else:
            logger.debug('nothing to clean from ' + title2clean)

    return True

def save_issue(data=None, eid=None, test_type=None):
    status = {'error': False}
    logger.debug('saving report issue')
    if not data:
        data = request.form
    if session:
        user_id = session['user_id']
    else:
        # if this is run manually from a python shell there's no session
        #user_id = 1
        status['error'] = 'could not find session, abandon adding issue'
        logerror(__name__, str(getframeinfo.lineno) + ': ' + status['error'])
        return status

    if not (eid and test_type):
        eid, test_type = get_engagement_id(test_type=True)

    issue_id = data['iid'] if 'iid' in data else data['id']
    issue_title = data['title'].strip()

    table = 'csa_reporting' if test_type == 'audit' else 'reporting'
    sql = 'select engagement_id, title from ' + table + ' where id = %s'
    qry = db_getdict(sql, (issue_id,))
    issue_meta = qry['data']
    issue2eid_map = { m['title'].strip(): m['engagement_id'] for m in issue_meta }

    #TODO this authorisation check can be streamlined if iid is passed as <iid> in the route?
    if issue2eid_map and issue_title in issue2eid_map:
        issue_eid = issue2eid_map[issue_title]
    else:
        status['error'] = 'could not find issue in ' + table + ' table: ' + issue_title
        logerror(__name__, getframeinfo(currentframe()).lineno, 'could not find issue in ' + table + ' table')
        logger.warn(status['error'])
        return status

    if issue_eid:
        current_eid = get_engagement_id()
        if int(issue_eid) != int(current_eid):
            status['error'] = 'Authorisation error: issue id ' + str(issue_id) + '(eid ' + str(issue_eid) +\
                              ') is not part of engagement id ' + str(current_eid)
            logger.warning(status['error'])
            return status
    else:
        status['error'] = 'failed to get issue_eid and test type for issue id ' + repr(issue_meta)
        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to get issue_eid and test type')
        logger.warn(status['error'])
        return status

    cmd = data['cmd']
    name = data['name']
    logger.debug('command is ' + data['cmd'])
    if cmd == 'savereplib':
        logger.debug('saving issue to report and library')
        if test_type == 'audit':
            update_csa_issue(data)
        else:
            update_issue(data)

        result = xhq.library.save(data)
        if result['error']:
            return result
    elif cmd == 'savelib':
        logger.debug('saving issue to library')
        result = xhq.library.save(data)
        if result['error']:
            return result
    elif cmd == 'saverep':
        logger.debug('saving issue to report')
        if test_type == 'audit':
            update_csa_issue(data)
        else:
            update_issue(data)
    elif cmd == 'getmerge':
        return '/get_merges/' + str(data['iid'])
    elif cmd == 'delrep':
        qry = db_getcol('select count(id) from reporting where engagement_id = %s', (current_eid,))
        if qry['success']:
            issue_count = qry['data'][0]
        else:
            frameinfo = getframeinfo(currentframe())
            logger.error('query failed: ' + frameinfo.filename + ':' + str(frameinfo.lineno))
            status['error'] = 'query failed'
            return status

        # deleting the last issue will trigger autosummary, which will return that issue (and others) straight back in
        if issue_count == 1:
            flash('Cannot delete the last finding in an engagement, please import or add other findings and try again (or delete the engagement).', 'error')
        else:
            logger.debug('deleting issue from report')
            if test_type == 'audit':
                db_do('update csa_reporting set deleted = true where id = %s', (data['iid'],))
            else:
                db_do('delete from servicevulns where report_vuln_id = %s', (data['iid'],))
                db_do('update reporting set deleted = true where id = %s', (data['iid'],))
    else:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'unrecognised save command: ' + str(cmd))

    if cmd == 'savelib':
        status['url'] = '/reporting/' + str(data['iid'])
        return status
    else:
        status['url'] = '/reporting/all'
        return status

def merge_issues(iid2merge_on):
    logger.debug('merging report issues')
    data = request.form
    eid = get_engagement_id()
    qry = db_getcol('select id from reporting where engagement_id = %s', (eid,))
    valid_iid_list = set(qry['data'])
    valid_iid_list.remove(int(iid2merge_on))
    merge = []
    for iid in data:
        if iid in ['csrf_token', 'merge_on_' + iid2merge_on]:
            continue
        elif int(iid) in valid_iid_list:
            merge.append(iid)
        else:
            flash('Error merging issues, at least one id could not be found in this engagement', 'error')
            logger.warning('invalid iid passed for merge: ' + str(iid))
            return False

    if merge:
        values = tuple([iid2merge_on] + merge)
        qry = db_do('update reporting set merged_with = %s where id in (' + '%s, '*(len(merge)-1) + '%s)', (values))
        if qry['success']:
            return True

    return False

def add_issue():
    result = {'success': False, 'status': '', 'errors': []}
    formdata = request.form
    #logger.debug(repr(formdata))

    user_id = session['user_id']
    # if this is run manually from a python shell there's no session
    # user_id = 1

    # ensure issue fields are sane, remove the unneeded bits like csrf and iid
    fields = ['name', 'severity', 'cvss3', 'cvss3_vector', 'exposure', 'description', 'details', 'discoverability',
              'exploitability', 'impact', 'remediation']
    issue = { k: formdata[k] for k in fields if k in formdata and formdata[k] }
    issue['title'] = formdata['name']

    cmd = formdata['cmd']
    result['status'] = 'saved2library' if cmd == 'savelib' else 'saved2report'

    if cmd == 'savelib':
        status = xhq.library.save(issue)
        result['success'] = False if status['error'] else True
        return result

    # this has to run for both saverep and savelibrep
    # ip addresses may not be unique so use a list
    affected_hosts = []
    i = 0
    while 'ip' + str(i) in formdata:
        ip = formdata['ip' + str(i)]
        hostname = formdata['hostname' + str(i)]

        if not ip and not hostname:
            logger.debug('empty row in issue host formdata, ignoring')
            i += 1
            continue

        if not is_ip(ip):
            logger.debug('invalid IP address for host ' + str(ip))
            result['errors'].append('invalid IP provided: ' + str(ip))

        hostname_regexp = '^[a-z][a-z0-9.-]{3,64}$'
        if hostname and not re.match(hostname_regexp, hostname):
            logger.debug('invalid hostname for host ' + str(i))
            result['errors'].append('Bad hostname value for host ' + str(i))

        port = formdata['port' + str(i)]
        if not re.match('\d{1,5}$', port):
            logger.debug('invalid port for host ' + str(i))
            result['errors'].append('Bad port value for host ' + str(i))

        protocol = formdata['protocol' + str(i)]
        protocol_regexp = '^[a-zA-Z]{2,12}$'
        if not re.match(protocol_regexp, protocol):
            logger.debug('invalid protocol for host ' + str(i))
            result['errors'].append('Bad protocol value for host ' + str(i))

        affected_hosts.append({'ip': ip, 'port': port, 'protocol': protocol, 'hostname': hostname})
        i += 1

    if result['errors']:
        return result

    eid = get_engagement_id()
    logger.debug('engagement id ' + eid + ', user ' + str(user_id))

    conn = get_db()
    curs = conn.cursor()
    # update the hosts and services tables with the submitted services, if needed
    external = True if formdata['exposure'] == 'external' else False
    status, affected_hosts = update_issue_services(curs, affected_hosts, external=external, eid=eid)
    if status['errors']:
        result['errors'] += status['errors']
        return result

    # add the issue to reporting table
    # doing this first allows to add the servicevuln entry without a second loop through hosts/services
    cols = list(issue.keys()) + ['engagement_id', 'ready']
    vals = list(issue.values()) + [eid, True]
    placeholders = '%s,'*(len(cols) - 1) + '%s'
    sql = 'insert into reporting (' + ','.join(cols) + ') values (' + placeholders + ') returning id'
    try:
        curs.execute(sql, tuple(vals))
    except psycopg2.errors.UniqueViolation:
        logger.warn('duplicate title for manual finding, aborting')
        result['errors'].append('A finding with this title and exposure already exists in this engagement')
        return result
    except Exception as e:
        logger.error(e.pgerror)
        logger.error(sql % tuple(vals))
        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to add finding to report')
        result['errors'].append('Error while saving finding')
        return result
    else:
        rid = str(curs.fetchone()[0])

    logger.debug('updated services for manual issue, saving findings')
    # check if an issue with this title/name exists in issues_seen
    logger.debug('looking for existing issues in issues_seen titled "' + issue['title'] + '"')
    qry = db_getrow('select id, title, description, severity, cvss3, cvss3_vector, remediation, impact, fingerprint\
                     from issues_seen where title = %s', (issue['title'],))
    if qry['success']:
        _data = qry['data']
    else:
        result['errors'] += qry['errors']
        return result
    # if issue exists, check fingerprint is the same, and update it if needed, otherwise create it
    # if a scanner import clashes with this title it will clobber the texts and should trigger the scanner text changed procedure
    current_fp = get_fingerprint(issue)
    if _data:
        issue_seen_id = _data['id']
        # if fp differs, store a version of the issue to the user's library
        if current_fp != _data['fingerprint']:
            # update the stored texts and fingerprint
            cols = ['title', 'description', 'severity', 'remediation']
            vals = [ issue[fld] for fld in cols ]
            cols.append('fingerprint')
            vals.append(current_fp)
            for fld in ['cvss3', 'cvss3_vector', 'impact']:
                if fld in issue:
                    cols.append(fld)
                    vals.append(issue[fld])

            vals.append(_data['id'])
            sql = get_pg_update_sql('issues_seen', cols, 'where id = %s')
            curs.execute(sql, tuple(vals))
            logger.debug('updated issues_seen texts for ' + issue['title'])
    else:
        cols = ['fingerprint', 'scanner']
        vals = [current_fp, 'manual']
        for fld in ['title', 'description', 'severity', 'cvss3', 'cvss3_vector', 'remediation', 'impact']:
            if fld in issue:
                cols.append(fld)
                vals.append(issue[fld])

        placeholders = '%s,'*(len(cols) - 1) + '%s'
        sql = 'insert into issues_seen (' + ','.join(cols) + ') values (' + placeholders + ') returning id'
        curs.execute(sql, tuple(vals))
        issue_seen_id = curs.fetchone()[0]
        logger.info('new manual issue stored: ' + issue['name'])

    # saved to report already, add to library if requested
    if cmd == 'savereplib':
        xhq.library.save(issue)
    elif cmd != 'saverep':
        result['errors'].append('unexpected parameters while saving finding')
        logerror(__name__, getframeinfo(currentframe()).lineno, '' + 'unrecognised cmd when saving manual issue: ' + str(cmd))
        return result

    # add entries in findings table, needed for reporting and perseverance across drop and summarise
    for host in affected_hosts:
        sid = host['sid']
        hostname = host['hostname']
        curs.execute("insert into findings (engagement_id, service_id, issue_id, external, vhost, scan_uri_list)\
                             values (%s, %s, %s, %s, %s, 'manual/1') returning id",
                            (eid, sid, issue_seen_id, external, hostname))
        fid = curs.fetchone()[0]

        logger.debug('adding issue to service mapping - iid/sid: ' + str(rid) + '/' + str(sid))
        curs.execute('insert into servicevulns (service_id, report_vuln_id, finding_id) values (%s, %s, %s)', (sid, rid, fid))

    # finally, add the summarised flag for the engagement if this is the first issue added
    qry = db_getcol('select count(id) from reporting where engagement_id = %s', (eid,))
    if qry['success']:
        if qry['data'][0] == 0:
            logger.info('setting summarised flag after manually adding the first issue')
            curs.execute('update engagements set summarised = true where eid = %s', (eid,))
    else:
        result['errors'] += qry['errors']
        logger.error('query failed')

    conn.commit()
    conn.close()
    result['success'] = True

    return result

def get_csa_report_data(template, rep, eid):
    #rep.setdefault('test_type', 'external internet-based')
    issues = {'failed': [], 'warning': [], 'passed': []}
    qry = db_getrow("select count(id) as num_total,\
                            count(id) filter (where compliance = 'FAILED') as num_failed,\
                            count(id) filter (where compliance = 'WARNING') as num_warning,\
                            count(id) filter (where compliance = 'PASSED') as num_passed\
                     from csa_reporting where deleted is false and merged_with is null and engagement_id = %s", (eid,))

    counts = qry['data']
    rep = {**rep, **counts}

    qry = db_getdict('select id, coalesce(name, title) as name, lower(compliance) as compliance, description, rationale,\
                             impact, remediation, reference\
                      from csa_reporting where deleted is false and merged_with is null and engagement_id  = %s\
                      order by name', (eid,))
    report_issues = qry['data']

    qry = db_getdict('select report_vuln_id, service_name\
                       from csa_servicevulns join csa_findings on finding_id = csa_findings.id\
                       where report_vuln_id in (select id from csa_reporting where engagement_id = %s)', (eid,))
    data = qry['data']
    affected = {}
    for entry in data:
        rid = entry['report_vuln_id']
        sn = entry['service_name']
        if rid in affected:
            affected[rid].append(sn)
        else:
            affected[rid] = [sn]

    qry = db_getcol('select service_name from csa_findings where engagement_id = %s group by service_name', (eid,))
    rep['scope'] = qry['data']

    for issue in report_issues:
        rid = issue['id']
        compliance = issue['compliance']
        description = RichText(issue['description'])
        remediation = RichText(issue['remediation'])
        rationale = RichText(issue['rationale'])
        reference = RichText(issue['reference'])
        impact = RichText(issue['impact'])
        services = affected[rid]

        #NOTE this is assuming unique titles across services
        # if multiple scans for different services are commonly reported on together may need an update
        report_issue = { 'title':           issue['name'],
                         'services':        services,
                         'description':     description,
                         'irationale':      rationale,
                         'reference':       reference,
                         'impact':          impact,
                         'remediation':     remediation }

        issues.setdefault(compliance, []).append(report_issue)

    rep.setdefault('issues', issues)

    logger.debug('data compiled, creating report document')

    return (template, rep)

def get_affected_services(iid, reportby='hostname', stats=False):
    '''Returns services affected by the passed report issue id
       in format {ip/hostname: {protocol: [port1, port2]}}
       Regardless of reportby value, will fall back to IP or hostname to avoid ambiguity'''

    qry = db_getdict('select coalesce(ipv4, ipv6) as ip, protocol, port, service, vhost, services.id as sid, hosts.id as hid\
                      from services\
                         join hosts on services.host_id = hosts.id\
                         join findings on service_id = services.id\
                      where findings.id in (select finding_id from servicevulns\
                                            where report_vuln_id in (select id from reporting\
                                                                     where id = %s or merged_with = %s))\
                       order by ip asc', (iid, iid))

    if not qry['data']:
        return {}
    else:
        data = qry['data']
        #logger.info(repr(data))

    vhosts = {}
    # compile a list of hostnames per ip
    hid_list = [str(s['hid']) for s in data]

    # host ids are serial type in db and should be safe
    hid_str = "'" + "','".join(hid_list) + "'"
    qry = db_getdict('select coalesce(ipv4, ipv6) as ip, virthost, webappurl\
                      from hosts\
                        left join http_virthost on hosts.id = http_virthost.host_id\
                        left join services on hosts.id = services.host_id\
                      where hosts.id in (' + hid_str + ')')

    if qry['success']:
        vhost_data = qry['data']
        #logger.debug(repr(vhost_data))
        if vhost_data:
            for host in vhost_data:
                if host['webappurl']:
                    vhosts.setdefault(host['ip'], set()).add(host['webappurl'])

                if host['virthost']:
                    vhosts.setdefault(host['ip'], set()).add(host['virthost'])
    else:
        logger.error('query failed')

    #logger.debug(repr(vhosts))

    affected = {}
    for host in data:
        ip = host['ip']
        protocol = host['protocol']
        # port has to be stored as string
        # append the service value (e.g. http) with a : as separator if collecting stats
        svc = host['service'] if host['service'] else ''
        port = str(host['port']) + '#' + svc if stats else str(host['port'])
        # by default get the vhost from the findings table entry for the issue
        vhost = host['vhost']
        if not vhost and ip in vhosts:
            vhost = list(vhosts[ip])[0]
            logger.debug('no webappurl stored, added first hostname as vhost: ' + vhost)

        #logger.debug('getting affected serices by ' + reportby)
        if reportby == 'hostname':
            if vhost:
                logger.debug('found vhost ' + vhost)
                if vhost in affected and protocol in affected[vhost]:
                    if port not in affected[vhost][protocol]:
                        affected[vhost][protocol].append(port)
                elif vhost in affected:
                    affected[vhost].setdefault(protocol, [port])
                else:
                   affected.setdefault(vhost, {protocol: [port]})
            elif ip:
                if ip in affected and protocol in affected[ip]:
                    if port not in affected[ip][protocol]:
                        affected[ip][protocol].append(port)
                elif ip in affected:
                    affected[ip].setdefault(protocol, [port])
                else:
                    affected.setdefault(ip, {protocol: [port]})
            else:
                logerror(__name__, getframeinfo(currentframe()).lineno, 'no IP or vhost for host')
                logger.warn(repr(host))
        else:
            if ip:
                # check if there's multiple vhosts for this ip
                # if a scan was done by IP (vhost is None), report by IP even if there are known hostnames for that IP
                if vhost and ((ip in vhosts and len(vhosts[ip]) > 1) or ip.startswith('0.0.0.')):
                    logger.debug('using IP ' + str(ip) + ' is ambiguous, falling back to hostname')
                    if vhost in affected and protocol in affected[vhost]:
                        if port not in affected[vhost][protocol]:
                            affected[vhost][protocol].append(port)
                    elif vhost in affected:
                        affected[vhost].setdefault(protocol, [port])
                    else:
                       affected.setdefault(vhost, {protocol: [port]})
                else:
                    if ip in affected and protocol in affected[ip]:
                        if port not in affected[ip][protocol]:
                            affected[ip][protocol].append(port)
                    elif ip in affected:
                        affected[ip].setdefault(protocol, [port])
                    else:
                        affected.setdefault(ip, {protocol: [port]})
            else:
                logerror(__name__, getframeinfo(currentframe()).lineno, 'no IP for host')
                logger.warn(repr(host))

    logger.debug('found ' + str(len(affected)) + ' affected services')
    return affected

def get_report_data(reportby):
    logger.debug('compiling report data by ' + reportby)
    rep = {}
    issues = {}
    if session:
        user_id = session['user_id']
        customer_id = session['customer_id']
    else:
        # if this is run manually from a python shell there's no session
        #user_id = 1
        logerror(__name__, getframeinfo(currentframe()).lineno, 'could not find session, abandon reporting')
        return False

    # get any custom templates
    qry = db_getrow('select pentest_template, audit_template as csa_template, vulnscan_template\
                     from customers where id = %s', (customer_id,))
    custom_templates = qry['data']

    app = Flask(__name__)
    app.config.from_object('def_settings')
    pentest_template = custom_templates['pentest_template']\
                        if custom_templates['pentest_template'] else app.config['PENTEST_TEMPLATE']
    csa_template = custom_templates['csa_template']\
                        if custom_templates['csa_template'] else app.config['AUDIT_TEMPLATE']
    vulnscan_template = custom_templates['vulnscan_template']\
                        if custom_templates['vulnscan_template'] else app.config['VULNSCAN_TEMPLATE']

    # use pentest template by default
    template = pentest_template

    logger.debug('compiling report data')
    # get engagement info
    qry = db_getrow('select eid, org_name, target_subnets, target_urls, extract(day from eng_start) as start_day,\
                       extract(day from eng_end) as end_day, extract(month from eng_end) as month, extract(year from eng_end) as year,\
                       contact1_name, contact1_email, contact1_phone, contact1_role, contact2_name, contact2_email, contact2_phone,\
                       contact2_role, test_type, target_type\
                     from engagements where active is true and user_id = %s', (user_id,))
    e = qry['data']
    eid = e['eid']
    test_type = e['test_type']
    qry = db_getrow("select name ||' '|| surname as author_name, email as author_email,\
                            phone as author_phone, user_type as author_role from users where id = %s", (user_id,))
    author_details = qry['data']
    logger.debug('set author to ' + repr(author_details['author_name']))
    # merge author details into the rest of the engagement info
    e = {**e, **author_details}

    for prm in ['org_name', 'contact1_name', 'contact1_email', 'contact1_phone', 'contact1_role',
                'contact2_name', 'contact2_email', 'contact2_phone', 'contact2_role',
                'author_name', 'author_role', 'author_email', 'author_phone']:
        rep.setdefault(prm, escape(e[prm]))

    d = date(int(e['year']), int(e['month']), int(e['end_day']))
    month = d.strftime('%B')
    year = d.strftime('%Y')
    rep.setdefault('start_day',  get_suffixed_number(int(e['start_day'])))
    rep.setdefault('end_day',  get_suffixed_number(int(e['end_day'])))
    rep.setdefault('month_year', month + ' ' + year)
    rep.setdefault('date', date.today().strftime("%d/%m/%Y"))

    # from here csa reporting gets different
    if test_type == 'audit':
        return get_csa_report_data(csa_template, rep, eid)

    scope = []
    if e['target_subnets']:
        for subnet in e['target_subnets'].split(','):
            scope.append(subnet.strip())
    if e['target_urls']:
        for url in e['target_urls'].split(','):
            scope.append(url.strip())
    rep.setdefault('scope', scope)
    logger.debug('scope is ' + repr(scope))

    counts = {}
    logger.debug('compiling data for pentest report')
    issues = { 'critical_ext': [], 'high_ext': [], 'medium_ext': [], 'low_ext': [], 'info_ext': [],
               'critical_int': [], 'high_int': [], 'medium_int': [], 'low_int': [], 'info_int': [],
               'critical_ad': [], 'high_ad': [], 'medium_ad': [], 'low_ad': [], 'info_ad': [] }
    qry = db_getrow("select count(id) filter (where exposure = 'external') as num_total_ext,\
                            count(id) filter (where exposure = 'external' and severity = 4) as num_crit_ext,\
                            count(id) filter (where exposure = 'external' and severity = 3) as num_high_ext,\
                            count(id) filter (where exposure = 'external' and severity = 2) as num_medium_ext,\
                            count(id) filter (where exposure = 'external' and severity = 1) as num_low_ext,\
                            count(id) filter (where exposure = 'external' and severity = 0) as num_info_ext,\
                            count(id) filter (where exposure = 'internal') as num_total_int,\
                            count(id) filter (where exposure = 'internal' and severity = 4) as num_crit_int,\
                            count(id) filter (where exposure = 'internal' and severity = 3) as num_high_int,\
                            count(id) filter (where exposure = 'internal' and severity = 2) as num_medium_int,\
                            count(id) filter (where exposure = 'internal' and severity = 1) as num_low_int,\
                            count(id) filter (where exposure = 'internal' and severity = 0) as num_info_int,\
                            count(id) filter (where exposure = 'adreview') as num_total_ad,\
                            count(id) filter (where exposure = 'adreview' and severity = 4) as num_crit_ad,\
                            count(id) filter (where exposure = 'adreview' and severity = 3) as num_high_ad,\
                            count(id) filter (where exposure = 'adreview' and severity = 2) as num_medium_ad,\
                            count(id) filter (where exposure = 'adreview' and severity = 1) as num_low_ad,\
                            count(id) filter (where exposure = 'adreview' and severity = 0) as num_info_ad\
                     from reporting where deleted is false and merged_with is null and engagement_id = %s", (eid,))
    counts = qry['data']
    rep = {**rep, **counts}

    logger.debug('getting report issues')
    qry = db_getdict('select id, coalesce(name, title) as name, severity, description, details, discoverability,\
                             exploitability, impact, remediation, exposure, cvss, cvss3, cvss3_vector, proof\
                      from reporting where deleted is false and merged_with is null and engagement_id  = %s\
                      order by severity desc, name', (eid,))
    report_issues = qry['data']
    logger.debug('got ' + str(len(report_issues)) + ' issues')

    logger.debug('getting affected hosts per issue')
    issues = {}
    appendices = []
    alphabet_iteration = 0
    for issue in report_issues:
        iid = issue['id']
        services = get_affected_services(iid, reportby=reportby)
        hostlist = []
        if not services:
            #TODO would be nice to alert people on report generation - will need some js
            logerror(__name__, getframeinfo(currentframe()).lineno, 'no affected services found for issue')
        else:
            hostlist = services.keys()

        hosts = []

        for ip in services:
            portstr = '; '.join([proto + '/' + ','.join(services[ip][proto]) for proto in services[ip]])
            hosts.append({'label': ip, 'ports': portstr})

        exposuremap = {'internal': 'int', 'external': 'ext', 'adreview': 'ad'}
        exposure = exposuremap[issue['exposure']]
        severity= issue['severity']
        s = {0: 'info', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        key = s[severity] + '_' + exposure
        #TODO this should be made consistent, proof is mostly used by pingcastle parser
        if issue['proof']:
            issue['description'] += '\n\n' + issue['proof']

        if issue['details']:
            issue['description'] += '\n\n' + issue['details']

        description = RichText(issue['description'])
        remediation = RichText(issue['remediation'])
        discoverability = RichText(issue['discoverability']) if issue['discoverability'] else None
        exploitability = RichText(issue['exploitability']) if issue['exploitability'] else None
        impact = RichText(issue['impact']) if issue['impact'] else None

        # deal with oversized host listings
        if len(hostlist) > 30:
            host_port_list = [ h['label'] + ':' + str(h['ports']) for h in hosts]
            # start appendices from D to allow for 3 default ones
            if appendices:
                # get the first char of the letter string
                letter = appendices[-1]['letter'][0]
                if letter == 'Z':
                    alphabet_iteration += 1
                    letter = 'A' + str(alphabet_iteration)
                else:
                    letter = chr(ord(letter) + 1) + str(alphabet_iteration) if alphabet_iteration else chr(ord(letter) + 1)
            else:
                letter = 'D'
            hostlist = ['Please see Appx. ' + letter]
            hosts = [{'label': hostlist[0], 'ports': ''}]
            appendixstr = '\n'.join(host_port_list)
            logger.debug('adding appendix ' + letter + ' for issue ' + issue['name'])
            appendices.append({'letter': letter, 'issue_name': issue['name'], 'content': appendixstr})

        if hostlist:
            try:
                hoststr = ', '.join(hostlist)
            except TypeError:
                logerror(__name__, getframeinfo(currentframe()).lineno, 'Bad value type for hostlist')
                logger.warn(repr(hostlist))
                hoststr = ''
        else:
            hoststr = ''

        report_issue = { 'title':           issue['name'],
                         'cvss3':           str(issue['cvss3']) if issue['cvss3'] else None,
                         'cvss3_vector':    issue['cvss3_vector'],
                         'hostlist':        hoststr,
                         'hosts':           hosts,
                         'description':     description,
                         'discoverability': discoverability,
                         'exploitability':  exploitability,
                         'impact':          impact,
                         'remediation':     remediation }

        issues.setdefault(key, []).append(report_issue)

    rep['issues'] = issues
    rep['appendices'] = appendices

    logger.debug('data compiled, creating report document (template: ' + template + ', appendices:' + str(len(appendices)) + ')')

    return (template, rep)

def del_issue_host(iid, sid = None):
    'deletes a host from the list of affected hosts for an issue'
    # authorise
    user_id = session['user_id']
    qry = db_getcol('select id from reporting\
                     where id = %s and engagement_id = (select eid from engagements\
                                                        where user_id = %s and active is true)', (iid, user_id))
    if not qry['data']:
        flash('Could not find issue ' + str(iid), 'error')
        logger.warn('refusing to delete serivice from issue not owned by user ' + str(user_id))
        return False

    if sid:
        logger.debug('deleting sid ' + str(sid) + ' from affected list for issue ' + str(iid))
        qry = db_do('delete from servicevulns\
                     where (report_vuln_id = %s or report_vuln_id in (select id from reporting where merged_with = %s))\
                        and service_id = %s', (iid, iid, sid))
        if qry['success']:
            return True
        else:
            logger.error('query failed')
    else:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'del_issue_host request without a sid')

    return False

def clear_summary():
    logger.debug('clearing issues from reporting tables for the active engagement')
    eid, test_type = get_engagement_id(test_type=True)

    if test_type == 'audit':
        qry = db_do('delete from csa_reporting where engagement_id = %s', (eid,))
    else:
        qry = db_do('delete from reporting where engagement_id = %s', (eid,))

    return qry['success']

def get_report_data_by_host():
    eid = get_engagement_id()
    qry = db_getrow('select id, coalesce(name, title) as name, severity, description, discoverability,\
                            exploitability, impact, remediation, exposure\
                     from reporting where deleted is false and merged_with is null and engagement_id  = %s\
                     order by name', (eid,), multi=True)

    issue_data = qry['data']
    logger.debug('got ' + str(len(issue_data)) + ' issues')
    result = []
    for issue in issue_data:
        iid = issue.pop('id')
        s = {0: 'info', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        severity = s[issue['severity']]
        qry = db_getdict('select ipv4, ipv6, virthost, protocol, port\
                          from services join hosts on services.host_id = hosts.id\
                                        left join http_virthost on hosts.id = http_virthost.host_id\
                          where services.id in (select service_id\
                                                from servicevulns\
                                                where report_vuln_id in (select id from reporting\
                                                                         where id = %s or merged_with = %s))\
                          order by ipv4 asc, ipv6 asc', (iid, iid))

        if qry['success'] and not qry['data']:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'issue affects no hosts')
            logger.warn(issue['name'])

        affected = qry['data']
        for host in affected:
            ip = host['ipv4'] if host['ipv4'] else host['ipv6']
            protocol = host['protocol']
            port = str(host['port'])
            hostname = host['virthost'] if host['virthost'] else ''
            #TODO: an IP of None should not be possible - remove root cause and this quick fix too
            # could be triggered when a host is deleted from an issue and then added again through merging issues
            if ip:
                #  ('IP', 'Hostname', 'Protocol', 'Port', 'Issue Name', 'Exposure', 'Severity', 'Description', 'Remediation')
                result.append([ip, hostname, protocol, port, issue['name'].strip(), issue['exposure'],
                               severity, issue['description'], issue['remediation']])
            else:
                logerror(__name__, getframeinfo(currentframe()).lineno, 'no IP in host')
                logger.warn(repr(host))

    return result

def get_discoverabilitylist(term):
    qry = db_getcol('select discoverability from library\
                     where lower(discoverability) similar to lower(%s)\
                     group by discoverability order by discoverability',
                            (term + '%',))
    if qry['success']:
        result = qry['data']
    else:
        result = []
        logger.error('query failed')

    return result

def get_exploitabilitylist(term):
    qry = db_getcol('select exploitability from library\
                     where lower(exploitability) similar to lower(%s)\
                     group by exploitability order by exploitability',
                            (term + '%',))
    if qry['success']:
        result = qry['data']
    else:
        result = []
        logger.error('query failed')

    return result

def get_ip(hostname):
    # if the hostname is seen in the active engagement for this user, return the ip
    # otherwise attempt to resolve the hostname
    eid = get_engagement_id()
    if eid:
        qry = db_getcol('select coalesce(ipv4, ipv6) as ip from hosts\
                         where engagement_id = %s and id in (select host_id from http_virthost where virthost = %s)\
                         group by ip', (eid, hostname))

        if qry['data']:
            result = qry['data'][0]
        else:
            logger.debug('no stored IP data for hostname ' + hostname)
            data = resolve(hostname)
            logger.debug('resolved to ' + repr(data))
            if data['ipv4']:
                result = data['ipv4']
            elif data['ipv6']:
                result = data['ipv6']
            else:
                result = 'no record'

    else:
        return None

    return result

def update_issue_services(curs, hostlist, external=False, eid=None):
    # take a list of hosts e.g. [ {'ip': ip, 'hostname': hostname, 'protocol': proto, 'port': port} ]
    # check existing hosts and services for the engagement and update them to include all of the above
    # return same data with added host and service ids for the relevant entries in db
    status = {'success': True, 'errors': []}
    if not eid:
        eid = get_engagement_id()

    # check if the hosts have been discovered by scanners and exist in db - within this engagement
    searchip = tuple(set([h['ip'] for h in hostlist]))
    if len(searchip) > 1:
        placeholders = '%s,'*(len(searchip) - 1) + '%s'
    else:
        placeholders = '%s'

    logger.debug('ipv4 in (' + placeholders + ') or ipv6 in (' + placeholders + '), ' + repr((eid,) + searchip + searchip))
    qry = db_getdict('select id, coalesce(ipv4, ipv6) as ip from hosts\
                      where engagement_id = %s\
                        and (ipv4 in (' + placeholders + ') or ipv6 in (' + placeholders + '))', (eid,) + searchip + searchip)

    if not qry['success']:
        logger.error('query failed')
        status['success'] = False
        status['errors'] += qry['errors']

    existing_hosts = qry['data']
    if existing_hosts:
        # compile a map for looking up host_id
        ehost_ipmap = { h['ip']: str(h['id']) for h in existing_hosts }

        search_hid = tuple(set(ehost_ipmap.values()))
        qry = db_getdict('select id, protocol, port, host_id, external, webappurl, scan_uri_list from services\
                          where host_id in (\'' + '\',\''.join(search_hid) + '\')')

        if not qry['success']:
            logger.error('query failed')
            status['success'] = False
            status['errors'] += qry['errors']

        logger.debug(repr(existing_hosts))
        existing_svcs = qry['data']
        # compile a map for looking up service_id
        ehost_svcmap = {}
        if existing_svcs:
            logger.debug(repr(existing_svcs))
            for s in existing_svcs:
                hid = str(s['host_id'])
                proto = s['protocol']
                port = str(s['port'])
                sid = str(s['id'])
                webappurl = s['webappurl'] if s['webappurl'] else ''

                if hid in ehost_svcmap:
                    ehost_svcmap[hid].setdefault(proto + port + webappurl, (sid, s['external'], s['scan_uri_list']))
                else:
                    ehost_svcmap.setdefault(hid, {proto + port + webappurl: (sid, s['external'], s['scan_uri_list'])})

    else:
        ehost_ipmap = {}
        ehost_svcmap = {}

    if not status['success']:
        return status

    logger.debug('saving any new hosts and/or services to database')
    for host in hostlist:
        ip = host['ip']
        port = host['port']
        protocol = host['protocol']
        hostname = host['hostname']
        if ip not in ehost_ipmap:
            ipv = str(is_ip(ip))

            curs.execute('insert into hosts (engagement_id, ipv' + ipv + ') values (%s, %s) returning id', (eid, ip))
            hid = str(curs.fetchone()[0])
            ehost_ipmap.setdefault(ip, hid)
            logger.debug('added host entry for ' + ip + ' mapped to hid ' + hid)

            if hostname:
                curs.execute('insert into http_virthost (host_id, virthost) values (%s, %s) on conflict do nothing', (hid, hostname))
                logger.debug('added hostname entry for ' + hostname)

        else:
            hid = ehost_ipmap[ip]
            logger.debug('ip already present in db, host_id ' + hid)

            if hostname:
                curs.execute('insert into http_virthost (host_id, virthost) values (%s, %s) on conflict do nothing', (hid, hostname))
                logger.debug('added hostname entry for ' + hostname)

        host['hid'] = hid

        svcstr = protocol + port + hostname if hostname else protocol + port
        if hid in ehost_svcmap and svcstr in ehost_svcmap[hid]:
            sid, isexternal, scan_uri_list = ehost_svcmap[hid][svcstr]
            logger.debug('servce already in db at service_id ' + sid)
            # this function is only called when manually adding hosts or issues
            # add a 'manual/N' scan_uri for compatibility and to allow for multiple issues to be manually added to a single service
            if re.search('manual', scan_uri_list):
                scan_uri_set = set(scan_uri_list.split(','))
                max_manual_id = 0
                for scan_uri in scan_uri_set:
                    scanner, _id = scan_uri.split('/')
                    if scanner == 'manual' and int(_id) > max_manual_id:
                        max_manual_id = int(_id)

                scan_uri = 'manual/' + str(max_manual_id + 1)
            else:
                scan_uri = 'manual/1'

            scan_uri_set.add(scan_uri)
            scan_uri_list = ','.join(scan_uri_set)

            if external and not isexternal:
                logger.debug('existing service stored as internal, updating to external')
                curs.execute('update services set external = %s, scan_uri_list = %s where id = %s', (external, scan_uri_list, sid))
            else:
                logger.debug('updating scan uri list for existing service')
                curs.execute('update services set scan_uri_list = %s where id = %s', (scan_uri_list, sid))
        else:
            logger.debug('storing service to db: ' + svcstr)
            scan_uri_list = 'manual/1'
            curs.execute('insert into services (host_id, protocol, port, external, webappurl, scan_uri_list)\
                                        values (%s, %s, %s, %s, %s, %s) returning id',
                                    (hid, protocol, port, external, hostname, scan_uri_list))
            sid = str(curs.fetchone()[0])
            logger.debug('stored service to db as: ' + str(sid))
            # a single issue is handled at a time but it may have multiple hosts
            if hid in ehost_svcmap:
                ehost_svcmap[hid].setdefault(svcstr, (sid, external, 'manual/1'))
            else:
                ehost_svcmap.setdefault(hid, {svcstr: (sid, external, 'manual/1')})

        host['sid'] = sid
        host['scan_uri_list'] = scan_uri_list

    #logger.debug(repr(hostlist))
    return (status, hostlist)

def add_issue_host(vid):
    '''adds a host/service to the affected list for a finding'''
    result = {'success': False, 'errors': []}
    # authorise request
    user_id = session['user_id']
    eid, test_type = get_engagement_id(test_type=True)
    reporting_table = 'csa_reporting' if test_type == 'audit' else 'reporting'
    qry = db_getcol('select id from ' + reporting_table + ' where id = %s and engagement_id = %s', (vid, eid))
    if qry['success']:
        if not qry['data']:
            logger.warn('refusing to add host to report issue ' + str(vid) + ': not owned by user ' + str(user_id))
            result['errors'].append('not authorised to modify this issue')
            return result
    else:
        logger.error('query failed')
        result['errors'].append('system error, please contact support')
        return result

    ip = request.form['ip0']
    hostname = request.form['hostname0']
    protocol = request.form['protocol0']
    port = request.form['port0']
    hostdata = [{'ip': ip, 'hostname': hostname, 'protocol': protocol, 'port': port}]

    conn = get_db()
    curs = conn.cursor()

    logger.debug('updating services for ' + repr(hostdata))
    status, updated = update_issue_services(curs, hostdata, eid=eid)

    if not status['success']:
        result['errors'] += status['errors']
        return result

    # logger.debug(repr(updated))
    qry = db_getrow('select issue_id, external, scan_uri_list from findings\
                     where id = (select finding_id from servicevulns where report_vuln_id = %s limit 1)', (vid,))
    if qry['success']:
        data = qry['data']
        issue_id = data['issue_id']
        external = data['external']
        scan_uri_list = data['scan_uri_list']
    else:
        result['errors'].append('server error, please contact support')
        logger.error('query failed: failed to get finding id for issue ' + str(vid))
        return result

    # hosts are added one at a time so the updated list should always contain one entry
    sid = updated[0]['sid']
    logger.debug('adding finding for service ' + sid + ' issue_id ' + vid)
    # since we are adding a single new finding for a service, just add a manual scan_uri
    # if the issue was manually added in the first place, should be ok to keep the scan_uri the same
    scan_uri_set = set(scan_uri_list.split(','))
    scan_uri_set.add('manual/1')
    scan_uri_list = ','.join(scan_uri_set)

    try:
        curs.execute('insert into findings (engagement_id, issue_id, external, service_id, vhost, scan_uri_list)\
                             values (%s, %s, %s, %s, %s, %s) returning id', (eid, issue_id, external, sid, hostname, scan_uri_list))
        fid = curs.fetchone()[0]
    except Exception as e:
        result['errors'].append('failed to add finding for issue ' + str(vid))
        logger.error(e.pgerror)
        logerror(__name__, getframeinfo(currentframe()).lineno, 'findings table insert failed')
        conn.close()
        return result

    logger.debug('adding issue to service mapping - iid/sid: ' + str(vid) + '/' + sid)
    try:
        curs.execute('insert into servicevulns (service_id, report_vuln_id, finding_id) values (%s, %s, %s)', (sid, vid, fid))
    except Exception as e:
        result['errors'].append('failed to add host for issue ' + str(vid))
        logger.error(e.pgerror)
        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to add host for issue')
        conn.close()
        return result

    conn.commit()
    conn.close()

    return result
