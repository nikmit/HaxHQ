import os
import time
import logging
from sys import path
from markupsafe import escape
from datetime import datetime
from flask import request, session
from inspect import currentframe, getframeinfo
from xhq.auth import authorise_access
from xhq.util import get_db, db_getrow, db_do, db_getcol, db_getdict, logerror, email_enabled

logger = logging.getLogger(__name__)
logger.setLevel('INFO')
#logger.setLevel('DEBUG')

def get_vars():
    data_retention = 60 #days
    user_id = session['user_id']
    res =  {'page': 'engagement', 'hidden_fields': ['Create new engagement', 'CSRF Token', 'Test type'], 'user': session['nickname'],
            'subtitle': 'Engagement', 'user_groups': session['user_groups'], 'engagements': [], 'isadmin': session['isadmin'],
            'has_stats': authorise_access('stats'), 'email_enabled': email_enabled()}

    qry = db_getdict('select eid, org_name, contact1_name, contact1_email, contact1_role, contact1_phone,\
                             contact2_name, contact2_email, contact2_role, contact2_phone, target_subnets,\
                             target_urls, notes, report_done, active, extract(epoch from eng_end) as eng_end, test_type, isdummy\
                      from engagements\
                      where user_id = %s\
                      order by eng_end desc', (user_id,))
    data = qry['data']
    active_seen = 0
    if data:
        #logger.debug(repr(data))
        for engagement in data:
            eng_end = datetime.fromtimestamp(int(engagement['eng_end'])).strftime('%d %b %y')
            eng_details = {'test_type': engagement['test_type'], 'eng_end': eng_end}
            if engagement['active']:
                if active_seen:
                    logerror(__name__, getframeinfo(currentframe()).lineno,
                             'there should never be more than one engagement active at a time')
                    qry = db_do('update engagements set active = false where user_id = %s', (user_id,))
                    if not qry['success']:
                        logger.error('failed to update engagements active flag')
                    return { 'error': 'multiple engagements marked active' }

                # set a flag that an active engagement exists
                active_seen = 1
                # load full information set for the active engagement
                logger.debug('found active engagement data')
                eng_details.setdefault('primary_contact', {'name': engagement['contact1_name']})
                for item in ['role', 'email', 'phone']:
                    if engagement['contact1_' + item]:
                        if item == 'email':
                            eng_details['primary_contact']['email'] = engagement['contact1_email']
                        else:
                            eng_details['primary_contact'][item] = engagement['contact1_' + item]

                if engagement['contact2_name']:
                    eng_details.setdefault('secondary_contact', {'name': engagement['contact2_name']})
                    for item in ['role', 'email', 'phone']:
                        if engagement['contact2_' + item]:
                            if item == 'email':
                                eng_details['secondary_contact']['email'] = engagement['contact2_email']
                            else:
                                eng_details['secondary_contact'][item] = engagement['contact2_' + item]

                if engagement['target_subnets']:
                    eng_details['subnets'] = engagement['target_subnets'].split(',')

                if engagement['target_urls']:
                    eng_details['urls'] = engagement['target_urls'].split(',')

                for item in ['eid', 'org_name', 'notes']:
                    eng_details[item] = engagement[item]

                eng_details['eng_end'] = datetime.fromtimestamp(int(engagement['eng_end'])).strftime('%d %b %y')

                logger.debug('active engagement loaded')
            else:
                # if this is not an active engagement get just basic info
                eng_details = { item:str(engagement[item]) for item in ['eid', 'org_name', 'test_type'] }
                max_age = engagement['eng_end'] + data_retention*24*60*60
                eng_details.setdefault('eng_end', datetime.fromtimestamp(int(engagement['eng_end'])).strftime('%d %b %y'))

                if engagement['isdummy'] or round(time.mktime(time.gmtime())) > max_age:
                    eng_details.setdefault('expired', 1)

            res['engagements'].append(eng_details)
    else:
        logger.debug('no engagements found')

    return res

def save_form():
    logger.debug('saving form')
    possible_keys = set([ 'org_name', 'target_subnets', 'target_urls', 'eng_start', 'eng_end', 'contact1_name',
                          'contact1_email', 'contact1_phone', 'contact1_role', 'contact2_name', 'contact2_email',
                          'contact2_phone', 'contact2_role', 'test_type', 'target_type', 'active' ])

    if 'user_id' in session:
        user_id = session['user_id']
    else:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'no user_id in session while saving engagement!')
        return False

    keys = ['user_id', 'active']
    values = [user_id, True]
    for key, value in request.form.items():
        if key not in ['submit', 'csrf_token'] and value:
            if key in ['target_subnets', 'target_urls']:
                val = value.replace(' ', '').replace('\n', '').replace('\t', '').replace('\r', '') if value else None
                if val:
                    keys.append(key)
                    values.append(val)

            elif key == 'org_name':
                keys.append(key)
                values.append(escape(value))
            elif key in possible_keys:
                keys.append(key)
                values.append(value)
            else:
                logger.warn('Invalid key seen in engagement form: ' + key)
                return False

    keystr = ', '.join(keys)
    valuestr = '%s, '*(len(values)-1) + '%s'

    logger.debug(keystr)
    logger.debug(valuestr)
    qry = db_do('insert into engagements (' + keystr + ') values (' + valuestr + ') returning eid', tuple(values))
    eid = qry['data']
    logger.debug('setting newly defined engagement as active')
    qry = db_do('update engagements set active = false where user_id = %s and eid != %s', (user_id, eid))
    if not qry['success']:
        logger.error('Failed to activate engagement after storing it, please contact support')
        flash('Failed to activate engagement after storing it, please contact support')
        return False

    return True

def activate(eid):
    if 'user_id' in session:
        user_id = session['user_id']
    else:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'no user_id in session while activating engagement!')
        return False

    # deactivate all
    qry = db_do('update engagements set active = false where user_id = %s', (user_id,))
    # activate eid
    if qry['success']:
        qry = db_do('update engagements set active = true where eid = %s and user_id = %s', (eid, user_id))
        if qry['success']:
            return {'success': True}

    return {'success': False}

def delete(eid):
    if 'user_id' in session:
        user_id = session['user_id']
    else:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'no user_id in session while attempting to delete engagement!')
        return False

    logger.debug('deleting engagement ' + str(eid))
    qry = db_do('delete from engagements where eid = %s and user_id = %s', (eid, user_id))

    return qry['success']

def create_dummy(eng_type, user_id=None):
    '''Creates and activates an engagement with arbitrary parameters for testing'''
    user_id = user_id if user_id else session['user_id']
    qry = db_do("insert into engagements (org_name, target_subnets, target_urls, eng_start, eng_end, contact1_name, contact1_email,\
                                          contact1_phone, contact1_role, contact2_name, contact2_email, contact2_phone, contact2_role,\
                                          test_type, isdummy, active, user_id)\
                                  values ('ACME Corp', '10.0.0.0/16', 'acmecorp.com',\
                                          LOCALTIMESTAMP(0), LOCALTIMESTAMP(0) + interval '1 day',\
                                          'John Smith', 'john.smith@acmecorp.com', '0123 465 789', 'CSO',\
                                          'Jane Smith', 'jane.smith@acmecorp.com', '0123 465 789', 'CEO', %s, true, true, %s)\
                                  returning eid",
                                  (eng_type, user_id))
    eid = qry['data']
    if eid:
        logger.debug('dummy engagement created, deactivating any other engagements')
        db_do('update engagements set active = false where user_id = %s and eid != %s', (user_id, eid))
    else:
        logerror(__name__, getframeinfo(currentframe()).lineno, 'failed to create a dummy engagement')
        return False

    return True
