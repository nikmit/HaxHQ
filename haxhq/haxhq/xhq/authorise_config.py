import copy
from flask import session

everyone = {
    'logout',
    'usersettings',
    'qrcode',
    'checktoken',
    'check_2fa',
    'contact',
    'enable_2fa',
    'disable_2fa',
    'colour_mode',
    'get',
    'getlogs',
    'get_cert'
}

allowed_routes = {  'hackers':
                    {
                        'engagement',
                        'dummy_eng',
                        'hacking',
                        'reporting',
                        'library',
                        'get_merges',
                        'merge_issues',
                        'add_host',
                        'add_issue',
                        'autoupdate_issues',
                        'generate_report',
                        'export_xlsx',
                        'export_iplist',
                        'activate',
                        'summarise_findings',
                        'del_issue_host',
                        'delete_engagement',
                        'upload_file',
                        'delete_scan',
                        'resolve_hostname'
                    } | everyone,

                    'csirt':
                    {
                        'stats'
                    } | everyone,

                    'manager':
                    {
                        'reports'
                    } | everyone
}

admin_routes = {'admin',
                'set_template',
                'get_template',
                'manage_users',
                'set_subscriber_mfa',
                'get_updates',
                'update',
                'disable_cert_auth',
                'enable_cert_auth',
                'update_login_logo'
               }

engagement_types = { 'csa':     [('audit','CSA Audit'), ('vulnscan','CSA Vuln')],
                     'cloud':   [('audit','CSA Audit')],
                     'hackers': [('pentest','Penetration Test')] }

def get_routes(group):
    if group in allowed_routes:
        routes = allowed_routes[group]
    elif group in ['csa', 'cloud']:
        routes = allowed_routes['hackers']
    else:
        routes = {}

    return routes

def get_default_route():
    if 'user_groups' in session:
        group = session['user_groups'][0]
        if group == 'csirt':
            return 'stats'
        elif group == 'manager':
            return 'reports'
        else:
            return 'engagement'
    else:
        return 'login'
