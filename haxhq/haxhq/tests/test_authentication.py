import requests

s = requests.Session()
logindata = {'username': 'nikmit', 'password':  'Di za zo2'}
#r = s.post('https://xhq.mitev.net:8443/login', logindata)
print('got session')
r2 = s.get('https://xhq.mitev.net:8443/engagement')
print(r2.title)
