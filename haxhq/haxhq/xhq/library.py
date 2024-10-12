import re
import time
import json
import copy
import logging
import difflib
from inspect import currentframe, getframeinfo
from flask import session, flash, Flask
from xhq.auth import authorise_access
from xhq.util import get_db, db_do, db_getcol, db_getrow, db_getdict, logerror, get_pg_update_sql, get_pg_insert_sql, email_enabled
from xhq.pingcastle_config import pcastle_issues

logger = logging.getLogger(__name__)
logger.setLevel('INFO')
logger.setLevel('DEBUG')

app = Flask(__name__)
app.config.from_object('def_settings')
scanners = app.config['SUPPORTED_SCANNERS']

issue_sources = scanners + ['manual']

def get_titlelist(term, _type=None):
    '''return a list of suggestions for the title search box'''

    result = []
    sql = 'select title, exposure from library where lower(title) like lower(%s) and customer_id = %s'
    param = ['%' + term.lower() + '%', session['customer_id']]
    if _type and _type != 'all':
        if _type in ['external', 'internal', 'adreview']:
            logger.debug('getting suggestions for ' + term + ' (' + repr(_type) + ')')
            sql += 'and exposure = %s'
            param.append(_type)
        elif _type in issue_sources:
            logger.debug('getting suggestions for ' + term + ' (' + repr(_type) + ')')
            sql += 'and lower(scanner) = %s'
            param.append(_type)
        else:
            logger.debug('getting suggestions for ' + term)
    else:
        logger.debug('getting suggestions for ' + term)

    qry = db_getdict(sql, tuple(param))
    if qry['success']:
        titlelist = [ '[' + i['exposure'][0] + '] ' + i['title'] for i in qry['data'] ]
    else:
        titlelist = []
        logger.error('query failed')

    logger.debug(repr(titlelist))
    return titlelist

def get_data(args=None):
    ''' returns template variables including any search results (library titles) for the customer_id, filtered by
        scanner and/or a search string; for empty search string returns all titles for the selected source.'''

    customer_id = session['customer_id']
    # define general variables needed by the template
    result = {'page': 'library', 'hidden_fields': ['CSRF Token'], 'user_groups': session['user_groups'], 'user': session['nickname'],
              'subtitle': 'Library', 'has_stats': authorise_access('stats'), 'isadmin': session['isadmin'], 'vuln': None,
              'email_enabled': email_enabled()}

    logger.debug('getting library issue listing for customer ' + customer_id)
    # collect the issues_seen list data, default to manual issues

    if args:
        sql = 'select title, exposure from library where customer_id = %s'
        param = [customer_id]
        if 'libsearchtype' in args and args['libsearchtype']:
            searchtype = args['libsearchtype'].lower()
            if args['libsearchtype'] in ['internal', 'external', 'adreview']:
                sql += ' and exposure = %s'
                param.append(searchtype)
            elif args['libsearchtype'] != 'all':
                param.append(searchtype)
                sql += ' and scanner = %s'

            if 'libsearchstr' in args and args['libsearchstr']:
                searchstr = args['libsearchstr'].lower()
                param.append('%' + searchstr + '%')
                sql += ' and lower(title) like lower(%s)'
                logger.debug('searching library for ' + searchtype + ' issues matching ' + searchstr)
            else:
                logger.debug('getting ' + searchtype + ' issues from library')

            sql += ' group by title, exposure order by title asc'
        else:
            # if unrecognised, ignore and return default data
            logger.warn('library search form submitted with unexpected parameters: ' + repr(args))

        # if there's a report issue id tracker in the form pass it along
        if 'repiid' in args and args['repiid']:
            result['repiid'] = args['repiid']
            logger.debug('added issue id to library page data: ' + str(result['repiid']))

        qry = db_getdict(sql, (tuple(param)))
        if qry['success']:
            result['data'] = qry['data']
        else:
            logger.error('query failed')
            result['data'] = {}

    return result

#def get_seen_issue(title):
#    '''returns details on seen issues for inspection in the library page'''
#    # data format needs to match the format from reporting.get_lib_issue() so the js load function can work
#    data = db_getrow('select severity, description, remediation, scanner from issues_seen where title = %s', (title,))
#    if data:
#        result = {'title': title, 'usermap': {0: data['scanner']}, 'user_list': [0], 'severity': data['severity']}
#        for text_type in ['description', 'remediation']:
#            result.setdefault(text_type, {0: data[text_type]})
#
#        return result
#    else:
#        return {}

def save(form):
    '''update library for the submitting user with the submitted data'''
    user_id = session['user_id']
    title = form['title'].strip()
    exposure = form['exposure'].strip()
    status = {'error': False}

    #TODO issue source is not being saved
    if 'cmd' in form and form['cmd'] == 'dellib':
        logger.debug('deleting library entry')
        qry = db_do('delete from library where title = %s and exposure = %s and user_id = %s returning id', (title, exposure, user_id))
        if qry['success']:
            if qry['data']:
                logger.debug('deleted library entry for user ' + str(user_id) + ' - ' + title)
            else:
                flash('users can only delete their own entries - consider creating a version that works for you instead', 'info')
                logger.debug('ignoring delete request for issue not belonging to user')
        else:
            status['error'] = 'failed to delete library entry'
            logger.error('failed to delete library entry for user ' + str(user_id) + ' - ' + title)

        return status

    libentry = dict(copy.copy(form))
    #TODO can iid be used to get scanner source more reliably, instead of selecting by title from issues_seen?
    for fld in ['cmd', 'details', 'csrf_token', 'iid', 'repiid']:
        if fld in libentry:
            del libentry[fld]
    #logger.debug(repr(libentry.keys()))
    libentry['user_id'] = user_id
    libentry['customer_id'] = session['customer_id']

    if title:
        # if title is defined, we are saving alternative texts for a scanner issue
        logger.debug('saving library entry for user ' + user_id + ' - ' + title)

        ### get scanner texts if any
        scanner_issue = None
        if 'severity' in form:
            logger.debug('getting scanner texts for pentesting issue')
            sql = 'select title, severity as orig_severity, cvss3 as orig_cvss3, cvss3_vector as orig_cvss3_vector,\
                          description as orig_description, impact as orig_impact, remediation as orig_remediation, scanner\
                   from issues_seen'
            if 'iid' in form and form['iid']:
                logger.debug('saving library entry for an edited issue - report iid: ' + str(form['iid']))
                sql += ' where id = (select issue_id from findings\
                                     where id in (select finding_id from servicevulns\
                                                  where report_vuln_id = %s)\
                                     group by issue_id)'
                prm = [form['iid']]
            else:
                logger.debug('saving library entry edited within library, or a manual finding')
                sql += ' where title = %s and scanner = (select scanner from library where title = %s group by scanner)'
                prm = [title, title]

            qry = db_getrow(sql, tuple(prm))
            if qry['success']:
                scanner_issue = qry['data']
                if scanner_issue:
                    if title == scanner_issue['title']:
                        logger.debug('identified {} issue in issues_seen'.format(scanner_issue['scanner']))
                    else:
                        logerror(__name__, getframeinfo(currentframe()).lineno,
                                 'failed to identify correct issue in issues_seen using iid')
                        logger.warn(repr(title) + ' != ' + repr(scanner_issue['title']))
                        return {'error': 'Error while saving library entry'}
                else:
                    logger.debug('failed to identify scanner issue, saving as a manual entry')
            else:
                logger.error('query failed')

        elif 'compliance' in form:
            logger.debug('getting scanner texts for csa issue')
            sql = 'select title, description as orig_description, impact as orig_impact, remediation as orig_remediation, scanner, \
                          rationale as orig_rationale, reference as orig_reference, see_also as orig_see_also from csa_issues_seen'
            if form['iid']:
                logger.debug('saving library entry for an edited issue - report iid: ' + str(form['iid']))
                sql += ' where id = (select issue_id from csa_findings\
                                     where id in (select finding_id from servicevulns\
                                                  where report_vuln_id = %s))'
                qry = db_getrow(sql, (form['iid'],))
                if qry['success']:
                    scanner_issue = qry['data']
                    if title != scanner_issue['title'].strip():
                        logerror(__name__, getframeinfo(currentframe()).lineno,
                                 'failed to identify correct issue in csa_issues_seen using iid')
                        return {'error': 'Error while saving library entry'}
                else:
                    logger.error('query error')
                    return {'error': 'Error while saving library entry'}
            else:
                sql += ' where title = %s'
                qry = db_getrow(sql, (title,))
                scanner_issue = qry['data']

        # if scanner texts have been found, merge them into the lib entry for tracking
        if scanner_issue:
            libentry = libentry | scanner_issue
        else:
            logger.debug('could not find scanner texts for ' + title)
            libentry['scanner'] = 'manual'
    else:
        logger.debug('creating new manual issue in library')
        title = libentry['name']
        libentry['title'] = title
        libentry['scanner'] = 'manual'

    cols = []
    vals = []
    for col, val in libentry.items():
        if val:
            cols.append(col)
            vals.append(val)

    # store entry in library
    # check for an existing entry with that title even for manual issues
    qry = db_getrow('select id from library where user_id = %s and exposure = %s and title = %s', (user_id, exposure, title))
    if qry['success']:
        existing_lib_entry = qry['data']
        if existing_lib_entry:
            logger.debug('found existing lib entry, updating id ' + str(existing_lib_entry['id']))
            vals.append(existing_lib_entry['id'])
            sql = get_pg_update_sql('library', cols, 'where id = %s')
        else:
            logger.debug('no issue found in this users library with this title, adding a new one')
            sql = get_pg_insert_sql('library', cols)
    else:
        status['error'] = 'Error while saving library entry'
        logger.error('query failed')
        return status

    #logger.debug(sql)
    qry = db_do(sql, tuple(vals))
    if qry['success']:
        logger.info('issue saved to library (' + str(user_id) + '): ' + form['title'])
    else:
        status['error'] = 'failed to save issue to library'
        logger.error(status['error'])

    return status

def get_lib_issue(title=None, exposure=None, lid=None):
    """Retrieves issue details from the issue library by title,
       and the default scanner texts from issues_seen.
       Used to populate issue edit form and to track scanner text changes"""
    if session:
        customer_id = session['customer_id']
        nickname = session['nickname']
    else:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'could not find session, abandon loading issue')
        flash('Invalid session, please log in again', 'error')
        return None

    result = {'issue_versions': {}, 'current_user': nickname, 'user_list': [] }

    sql = 'select nickname, title, coalesce(library.name, title) as name, severity, cvss3, cvss3_vector, description,\
                  discoverability, exploitability, impact, remediation, exposure\
           from library left join users on user_id = users.id\
           where library.customer_id = %s'
    prm = [customer_id]

    logger.debug('getting library issue for '+ repr((title, exposure, lid)))
    if title:
        m = re.match(r'^\[([iea])\] (.+)$', title)
        expmap = {'i': 'internal', 'e': 'external', 'a': 'adreview'}
        if m:
            exposure = expmap[m[1]]
            title = m[2]

        if exposure:
            m = re.match(r'^\[([iea])\]', exposure)
            if m:
                exposure = expmap[m[1]]

            logger.debug('checking library for ' + exposure + ' entry for ' + title)
            sql += ' and title = %s and exposure = %s'
            prm += [title, exposure]
        else:
            logger.debug('checking library for any entry matching ' + title)
            sql += ' and title = %s'
            prm.append(title)
    elif lid:
        logger.debug('getting library entry by id: ' + str(lid))
        sql += ' and library.id = %s'
        prm.append(lid)
    else:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'Bad parameters to get_lib_issue')
        logger.error('Bad parameters to get_lib_issue: ' + repr((title, exposure, lid)))
        return None

    # titles are unique for a user - unique (title, user_id)
    # get a list of issues matching the title, by user id, including the default scanner texts (if add_seen)
    # return the current user's version as the default and the rest as json for loading
    qry = db_getdict(sql, tuple(prm))
    library_texts = qry['data']

    if library_texts:
        logger.debug('found ' + str(len(library_texts)) + ' library texts')

        if not title:
            # when getting library texts by lib id there should only be one entry
            title = library_texts[0]['title']

        # no discoverability and exploitability columns so add null values to keep the same column set as above
        qry = db_getdict("select scanner as nickname, title, title as name, severity, cvss3, cvss3_vector, description,\
                                 null as discoverability, exploitability_ease as exploitability, impact, remediation\
                          from issues_seen\
                          where title = %s", (title,))
        scanner_texts = qry['data']
        logger.debug('found ' + str(len(scanner_texts)) + ' scanner texts')

        data = library_texts + scanner_texts
        logger.debug('found details for issue title: ' + data[0]['title'])
        result['issue_versions'] = { x.pop('nickname'): x for x in data }
        result['user_list'] = list(result['issue_versions'].keys())
        logger.debug(repr(result['user_list']))
    else:
        logger.info('no matching issue found in library: ' + repr((title, lid, exposure, customer_id)))


    return result

def get_suggestions(title, exposure=None, requested_nickname=None, autoupdate=False):
    ''' adds scanner text changes tracking to the data retrieved with get_lib_issue
        returns results for the requested user only '''

    title = title.strip()
    library_texts = {}
    metadata = {}

    data = get_lib_issue(title=title, exposure=exposure)

    if not data or not data['issue_versions']:
        logger.debug('no library entry for ' + title)
        return (library_texts, metadata)

    # get the latest scanner texts for comparing
    #NOTE this only tracks the texts from the initial scanner for which the library entry was created
    new_scanner_texts = None
    for n in data['user_list']:
        if n in scanners:
            # these are the latest scanner texts from issues_seen, which should get updated on every import
            logger.debug('found new scanner texts from ' + n)
            new_scanner_texts = data['issue_versions'].pop(n)
            data['user_list'].remove(n)
            break
    else:
        logger.debug(repr(data['user_list']))

    # pick the user/source of the library entry
    if requested_nickname:
        # ensure no access to library entries outside of team
        if requested_nickname not in data['user_list']:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'no library found for user')
            logger.error('no library found for user ' + requested_nickname)
            return (library_texts, metadata)
        else:
            nickname = requested_nickname
    elif session['nickname'] in data['user_list']:
        # if the logged in user has an entry, use it
        nickname = session['nickname']
    else:
        # otherwise fall back to an entry from the first tester in the team
        nickname = data['user_list'][0]

    library_texts = data['issue_versions'][nickname]

    # get the old scanner texts stored with the library issue
    # these are the texts based on which the library entry was created
    qry = db_getrow('select orig_description, orig_impact, orig_remediation, orig_rationale,\
                            orig_reference, orig_see_also, orig_severity, orig_cvss3, orig_cvss3_vector\
                     from library where title = %s and exposure = %s and user_id = (select id from users\
                                                                                    where nickname = %s and customer_id = %s)',
                                  (title, exposure, nickname, session['customer_id']))
    old_scanner_texts = qry['data']

    scanner_changes = {}
    if not (new_scanner_texts and old_scanner_texts):
        logger.debug('some scanner texts were not found in issues_seen, cannot track changes')
        debugstr = 'new_scanner_texts not found' if old_scanner_texts else 'old_scanner_texts not found'
        logger.info(debugstr)
        metadata = {'scanner_changes': scanner_changes, 'user_list': data['user_list']}
        return (library_texts, metadata)
    else:
        logger.debug('got old_scanner_texts for user ' + nickname)

    # compile scanner changes
    for text_type in new_scanner_texts:
        # some texts will be missing depending on the type of issue (csa/pentest)
        orig_text = 'orig_' + text_type
        if orig_text in old_scanner_texts and old_scanner_texts[orig_text]:
            if new_scanner_texts[text_type]:
                if text_type in ['severity', 'cvss3']:
                    ignored_text = str(old_scanner_texts[orig_text])
                    current_text = str(new_scanner_texts[text_type])
                else:
                    ignored_text = old_scanner_texts[orig_text].replace('\n', '').replace('\r', '').replace(' ', '').replace('\t', '')
                    current_text = new_scanner_texts[text_type].replace('\n', '').replace('\r', '').replace(' ', '').replace('\t', '')

                diff = difflib.SequenceMatcher(None, current_text, ignored_text)
                logger.debug('diff ratio: ' + str(round(diff.ratio(), 3)))
                if diff.ratio() > 0.995:
                    logger.debug(text_type + ' unchanged')
                    continue
                else:
                    logger.info(text_type + ' text changed')
                    scanner_changes.setdefault(text_type, {})
                    scanner_changes[text_type]['old_scanner_text'] = old_scanner_texts[orig_text]
                    scanner_changes[text_type]['new_scanner_text'] = new_scanner_texts[text_type]
                    scanner_changes[text_type]['libentry']  = library_texts[text_type]
                    #logger.debug(repr(scanner_changes))
                    library_texts[text_type] = new_scanner_texts[text_type]
            else:
                logger.info(text_type + ' has been removed from scanner texts')
        else:
            logger.debug(text_type + ' not found in old_scanner_texts')

    metadata = {'scanner_changes': scanner_changes, 'user_list': data['user_list']}

    return (library_texts, metadata)

def import_json(filename):
    ''' Import a json dump of library entires in format:
        user_id: title: {name: , severity: , description: , orig_description: , impact: , orig_impact: ,
                             remediation: , orig_remediation: , discoverability: , exploitability: , compliance: } '''

    with open(filename, 'r') as f:
        try:
            data = json.load(f)
        except Exception as e:
            logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to load invalid json')
            logger.error(repr(e))
            return False

    qry = db_getdict('select title, description, severity, remediation, impact, scanner from issues_seen')
    issues_seen = { x.pop('title'): x for x in qry['data'] } if qry['success'] else {}

    conn = get_db()
    curs = conn.cursor()

    for user_id in data:
        for title in data[user_id]:
            # copy the whole issue
            issue = data[user_id][title]['library']
            issue_seen = data[user_id][title]['issues_seen']
            # skip the entry unless both description and remediation are present
            if 'description' not in issue or not issue['description']:
                continue
            if 'remediation' not in issue or not issue['remediation']:
                continue

            # if no ignore (scanner) texts, assume it is a manual entry and import anyway
            for fld in ['description', 'remediation']:
                if title in issues_seen:
                    if not 'orig_' + fld in issue or not issue['orig_' + fld]:
                        issue['orig_' + fld] = issues_seen[title][fld]

                else:
                    # manual entry?
                    if not 'orig_' + fld in issue or not issue['orig_' + fld]:
                        issue['orig_' + fld] = 'none - manual?'

            if title in issues_seen:
                # only keep severity value for manual issues, otherwise override with the scanner one
                issue['severity'] = issues_seen[title]['severity']
                issue['scanner'] = issues_seen[title]['scanner']
                # scanner text could be missing for impact, add one so we don't lose the entry
                if 'impact' in issue and issue['impact']:
                    if issues_seen[title]['impact'] and ('orig_impact' not in issue or not issue['orig_impact']):
                        issue['orig_impact'] = issues_seen[title]['impact']
            elif issue_seen:
                issue['severity'] = issue_seen['severity']
                issue['scanner'] = issue_seen['scanner']
            else:
                continue
                #issue['scanner'] = 'manual'

            # store library
            issue['title'] = title
            issue['user_id'] = None
            cols = list(issue.keys())
            vals = list(issue.values())

            placeholders = '%s,'*(len(cols) - 1) + '%s'
            try:
                curs.execute('insert into library (' + ', '.join(cols) + ') values (' + placeholders + ')', tuple(vals))
            except Exception as e:
                logger.error(e.pgerror)
                logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to insert library entry')
                conn.close()
                return False

            # store issues seen
            issue_seen['title'] = title
            del issue_seen['name']
            cols = list(issue_seen.keys())
            vals = list(issue_seen.values())

            placeholders = '%s,'*(len(cols) - 1) + '%s'
            try:
                curs.execute('insert into issues_seen (' + ', '.join(cols) + ') values (' + placeholders + ')', tuple(vals))
            except Exception as e:
                logger.error(e.pgerror)
                logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to insert into issues_seen')
                conn.close()
                return False

    conn.commit()
    curs.close()

    return True
