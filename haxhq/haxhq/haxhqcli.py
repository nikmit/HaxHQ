import os
import sys
from flask import url_for
import xhq.admin

def main():
    usage = '''HaxHQ CLI - Limited CLI management interface to HaxHQ report automation tool

Usage:

haxhqcli check_connectivity         - Verify the local host connectivity. Checks DNS resolution and
                                      HTTPS connectivity to deb.debian.org, pypi.org and updates.haxhq.com.
                                      Checks SMTP connectivity to smtp.haxhq.com
         update_pass <email>        - Set or update a user's password. Will propmt for the password.
                                      Example: haxhqcli update_pass user@email.com
         enable_client_cert_auth    - Enable client certificate authentication and reload Nginx
         disable_client_cert_auth   - Disable client certificate authentication and reload Nginx
         get_client_cert <email>    - Issue a client certificate for the specified user and return the path to it
                                      in the local filesystem. Will prompt for the encryption password.
                                      Example: haxhqcli get_client_cert user@emal.com
         issue_server_cert          - Issue a server certificate for the local HaxHQ instance
                                      using the integrated certificate authority. Uses SENDER_DOMAIN from
                                      /opt/haxhq.com/haxhq/haxhq/def_settings.py to compile CN as haxhq.SENDER_DOMAIN.
         renew_server_cert          - Renew the server certificate for the local HaxHQ instance and install it.
                                      Issues a new CRL and reloads nginx.
         init_ca                    - Initialise the local Certificate Authority. You should only need to do this for
                                      the initial setup or or if the CA has been compromised.
                                      Deletes and invalidates all issued certificates!!!

This tool is intended as a fallback only, please use the web interface when possible.'''

    if len(sys.argv) == 2:
        command = sys.argv[1]
        email = None
    elif len(sys.argv) == 3:
        command = sys.argv[1]
        email = sys.argv[2]
    else:
        print(usage)
        sys.exit()

    if command:
        if command == 'check_connectivity':
            xhq.admin.check_env()

        elif command == 'update_pass':
            if email:
                print('Please enter the passphrase you want to use for HaxHQ:')
                password = input()
                status = xhq.admin.update_pass(password, email=email)
                if status['success']:
                    print('Password updated')
                else:
                    print(status['error'])
            else:
                print('Usage: update_pass <email> e.g. haxhqcli update_pass user@email.com')

        elif command == 'enable_client_cert_auth':
            result = xhq.admin.enable_cert_auth()
            if result['success']:
                print('Client certificate authentication enabled.')
            else:
                print(result['error'])

        elif command == 'disable_client_cert_auth':
            result = xhq.admin.disable_cert_auth()
            if result['success']:
                print('Client certificate authentication disabled.')
            else:
                print(result['error'])

        elif command == 'get_client_cert':
            if email:
                print('Please enter passphrase:')
                password = input()
                result = xhq.admin.get_client_cert(email, password)
                if result['success']:
                    print('Client certificate for '+ email +' issued: ' + result['data'][0])
                else:
                    print(result['error'])
            else:
                print('Usage: get_client_cert <email> e.g. haxhqcli get_client_cert user@email.com')

        elif command == 'issue_server_cert':
            result = xhq.admin.app_cert_issue()
            if result['success']:
                print('Server certificate issued and installed.')

        elif command == 'renew_server_cert':
            result = xhq.admin.app_cert_renew()
            if result['success']:
                print('Server certificate renewed and installed.')

        elif command == 'init_ca':
            print('You should only need to initialise the CA on initial installation. Proceeding will delete all issued certificates.')
            print("Please type 'yes' to continue or anything else to cancel:")
            yes = input()
            if yes == 'yes':
                result = xhq.admin.init_ca()
                if result['success']:
                    print('\nIntegrated Certificate Authority was rebuilt successfully.')
                else:
                    print(result['error'])
            else:
                print('Cancelled.')

        else:
            print(usage)
    else:
        print(usage)

if __name__ == "__main__":
    main()
