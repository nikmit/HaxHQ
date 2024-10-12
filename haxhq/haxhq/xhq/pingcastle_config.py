from datetime import datetime, timedelta

# Example report
# https://www.pingcastle.com/PingCastleFiles/ad_hc_test.mysmartlogon.com_auditor.html

categories = [
              'adminsdholder',
              'allprivileged',
              'certificateTemplates',
              'domaincontrollersdetail',
              'lapscreatedsid',
              'modalSchema-Administrators',
              'modalDomain-Administrators',
              'sectionbadprimarygroupcomputer',
              'sectionbadprimarygroupuser',
              'sectiondesenabledcomputer',
              'sectiondesenableduser',
              'sectionneverexpiresuser',
              'sectionpwdnotrequireduser',
              'sectionpwdnotrequiredcomputer',
              'sectionreversibleuser',
              'sectionsidhistoryuser',
              'sectionsidhistorycomputer',
              'rulesmaturity1A-DnsZoneUpdate1',
              'rulesmaturity1A-PwdGPO',
              'rulesmaturity1P-AdminPwdTooOld',
              'rulesmaturity1P-DisplaySpecifier,'
              'rulesmaturity1P-DNSDelegation',
              'rulesmaturity1T-SIDFiltering',
              #'rulesmaturity1P-Kerberoasting', #collected elsewhere
              'rulesmaturity2A-CertTempCustomSubject',
              'rulesmaturity2A-DC-Spooler',
              'rulesmaturity2P-DelegationKeyAdmin',
              'rulesmaturity2A-HardenedPaths',
              'rulesmaturity2A-MinPwdLen',
              'rulesmaturity2P-ControlPathIndirectMany',
              'rulesmaturity2P-DelegationKeyAdmin',
              'rulesmaturity2P-DelegationEveryone',
              'rulesmaturity2P-PrivilegeEveryone',
              'rulesmaturity2P-UnconstrainedDelegation',
              'rulesmaturity2S-ADRegistrationSchema',
              'rulesmaturity2S-PwdLastSet-90',
              'rulesmaturity2S-NoPreAuth',
              'rulesmaturity2S-OS-W10',
              'rulesmaturity2S-WSUS-HTTP',
              'rulesmaturity2T-FileDeployedOutOfDomain',
              'rulesmaturity2T-Inactive',
              'rulesmaturity3A-AuditDC',
              'rulesmaturity3A-CertEnrollHttp',
              'rulesmaturity3A-DCLdapsChannelBinding',
              'rulesmaturity3A-DCLdapSign',
              'rulesmaturity3A-DnsZoneUpdate2',
              'rulesmaturity3A-DsHeuristicsLDAPSecurity',
              'rulesmaturity3A-SHA1IntermediateCert',
              'rulesmaturity3A-SHA1RootCert',
              'rulesmaturity3A-WeakRSARootCert2',
              'rulesmaturity3P-DCOwner',
              'rulesmaturity3P-OperatorsEmpty',
              'rulesmaturity3P-ProtectedUsers',
              'rulesmaturity3P-RODCAllowedGroup',
              'rulesmaturity3S-DC-SubnetMissing',
              'rulesmaturity3S-PwdLastSet-45',
              'rulesmaturity3S-SMB-v1',
              'rulesmaturity3T-SIDHistoryUnknownDomain',
              'rulesmaturity4A-DnsZoneAUCreateChild',
              'rulesmaturity4P-UnkownDelegation',
              'rulesmaturity4T-AlgsAES',
]

# pingcastle issue titles which contain site-specific info
# need to look for matches in library using the generic part below
# NOTE longest match first!
pcastle_issues = [
    #check': lambda lastset: datetime.fromisoformat(lastset) > datetime.now() - timedelta(weeks=52*3) },
    #{ 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'A bogus Windows 2016 installation has granted too many rights to the Enterprise Key Admins group',
     'storenames': ['rulesmaturity2P-DelegationKeyAdmin'], 'sourcecols': ['DN', 'Account', 'Right'], 'col2check': None, 'check': None },

    {'title': 'A LDAP authentication without signature enforcement was allowed',
     'storenames': ['rulesmaturity3A-DCLdapSign'], 'sourcecols': ['Domain controller'], 'col2check': None, 'check': None },

    {'title': 'Account(s) with SID History matching the domain',
     # not useful, just a number or a list of unrelated account (not the ones matching the domain)
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'A large number of users or computers can take control of a key domain object by abusing targeted permissions',
     'storenames': ['rulesmaturity2P-ControlPathIndirectMany'], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'An explicit delegation has been put in place to manage the Microsoft DNS service.',
     'storenames': ['rulesmaturity1P-DNSDelegation'], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one certificate template can be modified by everyone',
     'storenames': ['certificateTemplates'], 'sourcecols': ['Name'], 'col2check': 'Vulnerable ACL',
     'check': lambda col2check: col2check == 'YES' },

    {'title': 'At least one certificate template can be requested by everyone having any purpose',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one certificate template used for authentication can have its subject modified when being used',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one GPO is deploying a file which can be modified by everyone',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one inactive trust has been found',
     'storenames': ['rulesmaturity2T-Inactive'], 'sourcecols': ['Trust'], 'col2check': None, 'check': None },

    {'title': 'At least one member of an admin group is vulnerable to the kerberoast attack',
     'storenames': ['allprivileged'], 'sourcecols': ['SamAccountName'], 'col2check': 'Service account',
     'check': lambda col2check: col2check == 'YES' },

    {'title': 'At least one policy has been found where the LM hash can be used',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one policy has been found where the reversible encryption has been enabled',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one trust DownLevel has been found. This is a NT4 compatible trust',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one trusted ROOT certificate found has a SHA1 signature',
     'storenames': ['rulesmaturity3A-SHA1RootCert'], 'sourcecols': ['GPO', 'Subject'], 'col2check': None, 'check': None },

    {'title': 'At least one trusted INTERMEDIATE certificate found has a SHA1 signature',
     'storenames': ['rulesmaturity3A-SHA1IntermediateCert'], 'sourcecols': ['GPO', 'Subject'], 'col2check': None, 'check': None },

    {'title': 'At least one trusted certificate found has a relatively weak RSA key',
     'storenames': ['rulesmaturity3A-WeakRSARootCert2'], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one trusted certificate found has a weak RSA key',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one user has an attribute set which is known to potentially contains a password',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one user, computer or group has been added as a member to the PreWin2000 compatible group',
     # no data available
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Channel binding is not enabled for all DC for LDAPS',
     'storenames': ['rulesmaturity3A-DCLdapsChannelBinding'], 'sourcecols': ['Domain controller'], 'col2check': None, 'check': None },

    {'title': 'Domain Controller(s) have been found where SMB signature is not enforced',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'domain controller(s) have been found where the owner is not the Domain Admins group or the Enterprise Admins group',
     'storenames': ['rulesmaturity3P-DCOwner'], 'sourcecols': ['Domain controller', 'Owner'], 'col2check': None, 'check': None },

    #XXX: dont move to alphabetical order, this needs to be above the entry below it
    {'title': 'unknown domain(s) used in SIDHistory',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'domain(s) used in SIDHistory',
     'storenames': ['rulesmaturity3T-SIDHistoryUnknownDomain'], 'sourcecols': ['SID', 'Object(s)'], 'col2check': None, 'check': None },

    {'title': 'DsHeuristics has not been set to enable the mitigation for CVE-2021-42291',
     'storenames': ['rulesmaturity3A-DsHeuristicsLDAPSecurity'], 'sourcecols': ['Setting', 'Value'], 'col2check': None, 'check': None },

    {'title': 'Hardened Paths have been modified to lower the security level',
     'storenames': ['rulesmaturity2A-HardenedPaths'], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Last change of the Kerberos password',
     'storenames': ['anomalies'], 'sourcecols': ['Kerberos password last changed'], 'col2check': None, 'check': None },

    {'title': 'Last AD backup has been performed',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'More than 15% of admins are inactive',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'More than 30% of admins are inactive',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'No GPO has been found which disables LLMNR or at least one GPO does enable it explicitly',
     # unclear data, not sure how policies interact with each other. More complex data extraction.
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'No GPO has been found which implements NetCease',
     # unclear data, not sure how policies interact with each other. More complex data extraction.
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'No GPO preventing the logon of administrators has been found.',
     # unclear data, not sure how policies interact with each other. More complex data extraction.
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'No password policy for service account found (MinimumPasswordLength>=20)',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Non-admin users can add up to 10 computer(s) to a domain',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of account(s) which have a reversible password',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of account(s) using a smart card whose password is not changed',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of accounts which can have an empty password (can be overridden by GPO)',
     'storenames': ['sectionpwdnotrequireduser', 'sectionpwdnotrequiredcomputer'], 'sourcecols': ['Name', 'Last logon'], 'col2check': None, 'check': None },

    {'title': 'Number of accounts which do not require kerberos pre-authentication',
     'storenames': ['rulesmaturity2S-NoPreAuth'], 'sourcecols': ['Account', 'Created', 'LastLogon'], 'col2check': None, 'check': None },

    {'title': 'Number of accounts which has never-expiring passwords',
     'storenames': ['sectionneverexpiresuser'], 'sourcecols': ['Name', 'Last logon'], 'col2check': None, 'check': None },

    {'title': 'Number of admin with a password older than 3 years',
     'storenames': ['rulesmaturity1P-AdminPwdTooOld'], 'sourcecols': ['Account', 'Creation', 'LastChanged'], 'col2check': None, 'check': None },

    {'title': 'Number of admins not in Protected Users',
     'storenames': ['rulesmaturity3P-ProtectedUsers'], 'sourcecols': ['User'], 'col2check': None, 'check': None },

    #XXX: this needs to be above the below one (longest match first)
    {'title': 'Number of computer without password change for at least 3 months',
     'storenames': ['rulesmaturity2S-PwdLastSet-90'], 'sourcecols': ['Computer', 'LastUsed', 'LastChange'], 'col2check': None, 'check': None },

    {'title': 'Number of computer without password change',
     'storenames': ['rulesmaturity3S-PwdLastSet-45'], 'sourcecols': ['Computer', 'LastUsed', 'LastChange'], 'col2check': None, 'check': None },

    {'title': 'Number of DC inactive',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of DC not updated',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of DC with a configuration issue',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of DC without password change',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    #XXX: this needs to be above the below one (longest match first)
    {'title': 'Number of DC with a constrained delegation with protocol transition',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of DC with a constrained delegation', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of files deployed hosted in another domain',
     'storenames': ['rulesmaturity2T-FileDeployedOutOfDomain'], 'sourcecols': ['Server', 'GPO', 'File'], 'col2check': None, 'check': None },

    {'title': 'Number of GPO items that can be modified by any user',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of login scripts hosted in another domain',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of login scripts that can be modified by any user',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of members of the Dns Admins group',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of password(s) found in GPO',
     'storenames': ['rulesmaturity1A-PwdGPO'], 'sourcecols': ['GPO', 'login', 'password'], 'col2check': None, 'check': None },

    {'title': 'Number of privileges granted by GPO to any user',
     'storenames': ['rulesmaturity2P-PrivilegeEveryone'], 'sourcecols': ['GPO', 'Account', 'Privilege'], 'col2check': None, 'check': None },

    {'title': 'Number of trusts without SID Filtering',
     'storenames': ['rulesmaturity1T-SIDFiltering'], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'operator group(s) are not empty',
     'storenames': ['rulesmaturity3P-OperatorsEmpty'], 'sourcecols': ['Group', 'Members'], 'col2check': None, 'check': None },

    {'title': 'Policy where the password complexity is less than 8 characters',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Policy where the password length is less than 8 characters',
     'storenames': ['rulesmaturity2A-MinPwdLen'], 'sourcecols': ['GPO'], 'col2check': None, 'check': None },

    {'title': 'Presence of accounts with non expiring passwords in the domain admin group',
     'storenames': ['modalDomain-Administrators'], 'sourcecols': ['SamAccountName'], 'col2check': 'Pwd never Expired',
     'check': lambda col2check: col2check == 'YES' },

    {'title': 'Presence of Admin accounts which do not have the flag "this account is sensitive and cannot be delegated"',
     'storenames': ['allprivileged'], 'sourcecols': ['SamAccountName'], 'col2check': 'Flag Cannot be delegated present',
     'check': lambda col2check: col2check == 'NO' },

    {'title': 'Presence of dangerous extended right in delegation',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Presence of delegation where anybody can act',
     'storenames': ['rulesmaturity2P-DelegationEveryone'], 'sourcecols': ['DN', 'delegation', 'right'], 'col2check': None, 'check': None },

    {'title': 'Presence of Des Enabled account',
     'storenames': ['sectiondesenableduser','sectiondesenabledcomputer'], 'sourcecols': ['Name','Last logon', 'Distinguished name'],
     'col2check': None, 'check': None },

    {'title': 'Presence of duplicate accounts',
     'storenames': ['sectionduplicatecomputer', 'sectionduplicateuser'], 'sourcecols': ['Name', 'Creation', 'Last logon', 'Distinguished name'],
     'col2check': None, 'check': None },

    {'title': 'Presence of non-supported version of Windows 10 or Windows 11',
     'storenames': ['rulesmaturity2S-OS-W10'], 'sourcecols': ['Version', 'Number', 'Active'], 'col2check': None, 'check': None },

    {'title': 'Presence of non supported Windows 10',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Presence of restricted group where anybody is a member',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Presence of service accounts in the domain admin group',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Presence of unknown account in delegation',
     'storenames': ['rulesmaturity4P-UnkownDelegation'], 'sourcecols': ['DN', 'delegation', 'right'], 'col2check': None, 'check': None },

    {'title': 'Presence of vulnerable schema class',
     'storenames': ['rulesmaturity2S-ADRegistrationSchema'], 'sourcecols': ['Class', 'Vulnerability'], 'col2check': None, 'check': None },

    {'title': 'Presence of Windows 2000',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Presence of Windows 2003',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Presence of Windows 2008',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Presence of Windows 7',
     # command available, data not very useful (just a total number)
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Presence of Windows 8',
     # command available, data not very useful (just a total number)
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Presence of Windows XP',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Presence of wrong primary group for computers',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Presence of wrong primary group for users',
     'storenames': ['sectionbadprimarygroupcomputer', 'sectionbadprimarygroupuser'], 'sourcecols': ['Name', 'Last logon'], 'col2check': None, 'check': None },

    {'title': 'Relatively high number of inactive computer accounts',
     # no details, command provided in description
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Relatively high number of inactive user accounts',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'SMB v1 activated on',
     'storenames': ['rulesmaturity3S-SMB-v1'], 'sourcecols': ['Domain controller'], 'col2check': None, 'check': None },

    {'title': 'Suspicious admin activities detected',
     'storenames': ['adminsdholder'], 'sourcecols': ['Name', 'Event date', 'Last logon'], 'col2check': None, 'check': None },

    {'title': 'The Allowed RODC Password Replication Group group is not empty',
     'storenames': ['rulesmaturity3P-RODCAllowedGroup'], 'sourcecols': ['Member'], 'col2check': None, 'check': None },

    {'title': 'The audit policy on domain controllers does not collect key events.',
     'storenames': ['rulesmaturity3A-AuditDC'], 'sourcecols': ['Domain controller', 'Audit', 'Problem', 'Rationale'], 'col2check': None, 'check': None },

    {'title': 'The group Schema Admins is not empty',
     'storenames': ['modalSchema-Administrators'], 'sourcecols': ['SamAccountName'], 'col2check': None, 'check': None },

    {'title': 'The local admin password of at least one computer can be retrieved by the user who joined the computer to the domain',
     'storenames': ['lapscreatedsid'], 'sourcecols': ['Name', 'Creation', 'Last logon'], 'col2check': None, 'check': None },

    {'title': 'The native administrator account has been used recently',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The number of DCs is too small to provide redundancy',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The password used in Azure AD SSO has not been changed for at least one year',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The PowerShell audit configuration is not fully enabled',
     # needs aditional processing to get the data - all policies where Setting begins with Powershell?
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The spooler service is remotely accessible',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The subnet declaration is incomplete',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Unconstrained delegations are configured on the domain',
     'storenames': ['rulesmaturity2P-UnconstrainedDelegation'], 'sourcecols': ['Name', 'DN'], 'col2check': None, 'check': None },

    {'title': 'Users in Admins groups',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'WSUS is configured with http instead of https',
     'storenames': ['rulesmaturity2S-WSUS-HTTP'], 'sourcecols': ['GPO', 'Server'], 'col2check': None, 'check': None },
#############
#############
    {'title': 'Domain Controller(s) have been found where SMB signature is not enabled',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': "The Protected Users group doesn't exist on the domain.",
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': "LAPS doesn't seem to be installed", 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of DC(s) vulnerable to MS17-010', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of DC(s) vulnerable to MS14-068', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Non-admin users can add up to ', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one trusted ROOT certificate found has a SHA0 signature',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one trusted ROOT certificate found has a MD5 signature',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one trusted ROOT certificate found has a MD4 signature',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one trusted ROOT certificate found has a MD2 signature',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one trusted INTERMEDIATE certificate found has a SHA0 signature',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one trusted INTERMEDIATE certificate found has a MD2 signature',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one trusted INTERMEDIATE certificate found has a MD4 signature',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The SIDHistory auditing group is present: SID History creation is enabled',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of DC(s) with NULL SESSION enabled', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The group Everyone and/or Anonymous is present in the Pre-Windows 2000 group.',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one trusted INTERMEDIATE certificate found has a MD5 signature',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one policy has been found where the account having an empty password can be accessed from the network',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'policies have been found where anonymous accesses can be used',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'DsHeuristics has been set to allow anonymous sessions.',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Presence of Windows NT', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of computers which have a reversible password',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Exchange did alter the AdminSDHolder object', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The group Exchange Windows Permissions has the right to change the security descriptor of the domain root',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Anyone can interactively or remotely login to a DC',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The Recycle Bin is not enabled', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The AdminSDHolder safety mechanism has been modified for some privilege groups',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The DoListObject has been enabled', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one GPO grant the right to get in the recovery mode without being admin',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one GPO disables explicitly LDAP client signature',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one GPO disables explicitly the change of the computer account password',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one forest trust has been found where TGT delegation over forest trust is allowed',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The privilege "Access Credential Manager as a trusted caller user right" has been explicitly granted.',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Everyone can take control of a key domain object by abusing targeted permissions.',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one DC uses a weak SSL protocol for server side purposes.',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Presence of Windows Vista', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one private key associated to a certificate can be recovered',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one trusted certificate found has a DSA key',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one trusted certificate found has a weak RSA exponent',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'DsHeuristics has been set to allow anonymous access to the NSPI protocol',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The Denied RODC Password Replication Group group has some of its default members missing',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The old protocol NTFRS is used to replicate the SYSVOL share',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'A DNS Zone is configured with unsecure updates',
     'storenames': ['rulesmaturity3A-DnsZoneUpdate2'], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of dangerous SID in SIDHistory', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of DC with a resource based constrained delegation',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Number of admin accounts which do not require kerberos pre-authentication',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one privileged group can be revealed on RODC',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The protection against Privileged Group protection on RODC is not fully enabled',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one privileged user has been revealed on a RODC',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one RODC has write access to the SYSVOL volume',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'A DNS Zone is configured with Zone Transfers enabled',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one certificate template can be used to issue agent certificate to everyone',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The PreWin2000 compatible group contains "authenticated users"',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The Java schema extension has been found', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'WSUS is configured to accept user proxy', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The Certificate Pinning security of WSUS has been disabled',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one WSUS server uses a weak SSL protocol.',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'DsHeuristics has been set to disable the UPN or SPN uniqueness check',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The Guest account of the domain is enabled', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Authenticated Users can create DNS records', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The certificate enrollment interface is accessible by HTTP',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Channel Binding is not enforced for the HTTPS certificate enrollment interface',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'AES is not enabled on all trusts', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'At least one certificate template has the flag CT_FLAG_NO_SECURITY_EXTENSION set',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The WebClient service which allows WebDAV communication is enabled',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Verify Kerberos Armoring is enabled on DCs and the functional level is at least Windows 2012',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'Verify Kerberos Armoring is enabled on clients and the functional level is at least Windows 2012',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'DisplaySpecifier scripts have been identified and they are not stored in the sysvol directory.',
     'storenames': ['rulesmaturity1P-DisplaySpecifier'], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The functional level is below Windows 2008 R2.', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The functional level is below Windows 2012 R2.', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The functional level is below Windows 2016.', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },

    {'title': 'The LAN Manager Authentication Level allows the use of NTLMv1 or LM.',
     'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },
    #XXX this one is a pain: More than {threshold}% of admins are inactive: {count}%
    {'title': 'More than ', 'storenames': [], 'sourcecols': [], 'col2check': None, 'check': None },
]
    
