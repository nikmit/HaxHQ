import logging
import ipaddress
from xhq.util import get_db, db_do, db_getdict, db_getcol, is_ip, logerror, resolve

logger = logging.getLogger(__name__)
logger.setLevel('INFO')
#logger.setLevel('DEBUG')

# import amass text file in format
# domain.tld IP1 IP2 IPn - ips can be v4 or v6 or mix of both
# loop through list, check domain resolves to IP as listed (could be redundant, log if diff found)
# check IP is in scope

def parse(filename):
    with open(filename) as f:
        data = {}
        cnames = {}
        for line in f:
            parts = line.split(' ')
            if parts[3] == 'a_record':
                ip = parts[5]
                fqdn = parts[0]
                logger.debug(repr(ip))

            elif parts[3] == 'ptr_record':
                ptr_parts = parts[0].split('.')
                ip = '.'.join([ptr_parts[3],ptr_parts[2],ptr_parts[1],ptr_parts[0]])
                logger.debug(repr(ip))
                fqdn = parts[5]

            elif parts[3] == 'cname_record':
                cname = parts[5]
                fqdn = parts[0]
                #store as cname and stop processing this line
                logger.debug('cname record')
                cnames[fqdn] = cname
                continue

            else:
                logger.debug('unrecognised line ignored: ' + line)
                continue

            if is_ip(ip):
                data.setdefault(ip, [])
                data[ip].append(fqdn)
            else:
                logger.debug('unrecognised data ignored: ' + ip)

        return (data,cnames)

def import_scan(filename, eid):
    status = {'error': False}
    data,cnames = parse(filename)
    if not data and not cnames:
        logger.warning('no data recognised in: ' + filename)
        status['error'] = 'no data recognised in file'
        return status

    qry = db_getdict('select id, ipv4, ipv6, fqdn from hosts where engagement_id = %s', (eid,))
    existing_hosts = qry['data']
    existing_data = {}
    hostmap = {}
    fqdnmap = {}
    for host in existing_hosts:
        ip = host['ipv4'] if host['ipv4'] else host['ipv6']
        existing_data.setdefault(ip, {'id': host['id'], 'fqdn': host['fqdn']})
        # even if both v4 and v6 defined it is fine to use just v4 for mapping
        hostmap[host['id']] = ip
        fqdnmap[host['fqdn']] = host['id']
        if host['ipv4'] and host['ipv6']:
            # if both v4 and v6 addresses defined, add an entry for the v6 too
            existing_data.setdefault(host['ipv6'], {'id': host['id'], 'fqdn': host['fqdn']})

    # get engagement scope
    qry = db_getcol('select target_subnets from engagements where eid = %s', (eid,))
    if qry['data']:
        subnet_str = qry['data'][0]
        logger.debug(subnet_str)
        subnets = [ipaddress.ip_network(x.strip()) for x in subnet_str.split(',')]
        logger.debug(repr(subnets))
    else:
        logger.info('failed to get subnets from engagement')
        status['error'] = 'No subnets defined for the current engagement, aborting amass import'
        return status

    conn = get_db()
    curs = conn.cursor()
    if data:

        for ip in data:
            logger.debug('processing host ip ' + ip)
            if ip in existing_data:
                logger.debug(ip + ' already exists in db')
                host_id = existing_data[ip]['id']
                for vhost in data[ip]:
                    if not existing_data[ip]['fqdn']:
                        # if no fqdn stored, add this vhost as fqdn
                        logger.debug('no stored FQDN, updating to ' + vhost)
                        curs.execute('update hosts set fqdn = %s where id = %s', (vhost, host_id))
                        logger.debug('adding ' + vhost + ' to fqdnmap')
                        fqdnmap[vhost] = host_id
                    elif not existing_data[ip]['fqdn'] == vhost:
                        # if fqnd exists but is not same as vhost, add to list of virthosts
                        logger.debug('existing fqdn is different, adding vhost: ' + vhost)
                        curs.execute('insert into http_virthost (host_id, virthost) values (%s, %s) on conflict do nothing',
                                    (host_id, vhost))
                        logger.debug('adding ' + vhost + ' to fqdnmap')
                        fqdnmap[vhost] = host_id

            # dont add hosts which have not been detected as having exposed services
#            else:
#                # check the IP is in scope
#                _ip = ipaddress.ip_address(ip)
#                for subnet in subnets:
#                    if _ip in subnet:
#                        break
#                else:
#                    logger.debug(ip + ' is out of scope, skipping')
#                    continue
#
#                logger.debug('adding new host ' + ip)
#                ipv = 'ipv' + str(is_ip(ip))
#                sql = 'insert into hosts (engagement_id, ' + ipv + ') values (%s, %s) returning id'
#                curs.execute(sql, (eid, ip))
#                host_id = curs.fetchone()[0]
#                for vhost in data[ip]:
#                    curs.execute('insert into http_virthost (host_id, virthost) values (%s, %s) on conflict do nothing',
#                                    (host_id, vhost))
#
#                logger.debug('added host with id ' + str(host_id))
#                # update existing_data cache to reflect new db state
#                existing_data.setdefault(ip, {'id': host_id, 'fqdn': vhost})

    if cnames:
        logger.debug('cnames seen, processing')
        for fqdn, cname in cnames.items():
            if fqdn in fqdnmap and cname in fqdnmap:
                logger.debug('both known, skipping: ' + fqdn + ', ' + cname)
                continue
            elif cname in fqdnmap:
                host_id = fqdnmap[cname]
                fqdn2add = fqdn
                # host exists, just add the fqdn below
            elif fqdn in fqdnmap:
                host_id = fqdnmap[fqdn]
                fqdn2add = cname
                # host exists, just add the cname below
            else:
                logger.debug('host not found, ignoring fqdns for ip without visible services: ' + fqdn + '/' + cname)
                continue

            curs.execute('insert into http_virthost (host_id, virthost) values (%s, %s) on conflict do nothing',
                                (host_id, fqdn2add))
            logger.debug('added fqdn ' + fqdn2add + 'to host id ' + str(host_id))
            # update existing_data cache to reflect new db state
            existing_data.setdefault(ip, {'id': host_id, 'fqdn': fqdn2add})

    conn.commit()
    curs.close()
    logger.debug('amass import comleted')
    return status

def main():
    filename = sys.argv[1]
    parse(filename)

if __name__ == "__main__":
    main()
