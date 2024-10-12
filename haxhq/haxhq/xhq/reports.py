import re
import logging
from datetime import date, timedelta
from flask import session, request, flash
import xhq.mkdoc
from xhq.util import db_getrow, db_getcol, db_getdict, db_do, logerror

logger = logging.getLogger(__name__)
logger.setLevel('INFO')
logger.setLevel('DEBUG')

def get_vars():
    '''collects the data required to display the manager reports page'''
    status = {'error': False}

    # prepopulate the result with the static elements
    result = { 'page': 'reports', 'subtitle': 'Reports', 'has_stats': False, 'user': session['nickname'],
               'user_groups': session['user_groups'], 'isadmin': session['isadmin'], 'hidden_fields': ['Submit', 'CSRF Token'] }

    qry = db_getdict("select substring(eng_start::text from 0 for 11) as start,\
                             substring(eng_end::text from 0 for 11) as end, org_name as organisation, report_done,\
                             count(reporting.id) filter (where severity > 0) as vulnerabilities,\
                             concat(users.name, ' ', surname) as tester\
                      from engagements\
                        join users on user_id = users.id\
                        join reporting on eid = engagement_id\
                      where test_type = 'pentest'\
                      group by eng_start, eng_end, organisation, report_done, users.name, surname\
                      order by start desc\
                      limit 20")

    if qry['success']:
        result['engagements'] = qry['data']
    else:
        result['engagements'] = []
        status = {'error': True}

    return status, result

def get_internal_report_data(prefix='Jisc INT', rep_from=None, rep_to=None):
    '''Extracts vulnerability data (severity, name, resolution) from pentests over a period back from the current date'''

    rep_from = rep_from if rep_from else date.today(-7).strftime('%d/%m/%Y')
    rep_to = rep_to if rep_to else date.today().strftime('%d/%m/%Y')
    logger.debug('getting internal engagements data for period from ' + rep_from + ' to ' + rep_to)

    qry = db_getdict("""select severity, coalesce(name, title), substring(org_name from 9) as service, remediation
                        from reporting
                           join engagements on engagement_id = eid
                        where org_name like %s
                           and eng_start > %s
                           and eng_end < %s
                           and severity > 0
                           and report_done is true
                        order by severity desc""", (prefix + '%', rep_from, rep_to))

    data = qry['data']
    s = {0: 'Info', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}
    if data:
        logger.debug('matching engagements found, prefix: ' + prefix)
        for entry in data:
            m = re.match('^[\s:-]+(.+)$', entry['service'])
            entry['service'] = m[1]
            entry['severity'] = s[entry['severity']]

        return data

    else:
        logger.debug('no engagements starting with ' + prefix + ' seen between ' + rep_from + ' and ' + rep_to)
        return None

def generate_internal_report(rep_from=None, rep_to=None):

    data = get_internal_report_data(rep_from=rep_from, rep_to=rep_to)
    if data:
        reportfile = xhq.mkdoc.create_xlsx_report(data)
        logger.debug('report generated: ' + reportfile)
        return reportfile
    else:
        logger.debug('no data to report on')
        return None

