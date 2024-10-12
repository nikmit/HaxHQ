#!/usr/bin/env python3
import logging
import sys
#import os
#import pprint
#import re
#import ipaddress
import xml.etree.ElementTree as etree
from xhq.util import is_ip, get_db, db_do, db_copy, db_getcol, db_getrow, db_getdict, resolve, get_pg_update_sql

logger = logging.getLogger(__name__)
logger.setLevel('INFO')

def parse(filename):
    try:
        tree = etree.parse(filename)
    except Exception as error:
        print("Error: {}".format(error))
        exit()

    res = {}
    root = tree.getroot()
    nmap_args = root.get('args')
    for host in root.findall('host'):
        if host.find('status').attrib['state'] == 'down':
            continue

        ip = host.find('address').attrib['addr']
        hostnames = [ hn.attrib['name'] for hn in host.find('hostnames')]

        os_element = host.find('os')
        if os_element:
            os_names = [ osmatch.attrib['name'] for osmatch in os_element.findall('osmatch') ]
        else:
            os_names = []

        host_data = {ip: {'hostnames': hostnames, 'os': os_names}}

        ports_el = host.find('ports')
        if ports_el:
            ports = ports_el.findall('port')
            for port in ports:
                if not port.find('state').attrib['state'] == 'open':
                    continue
    
                proto = port.attrib['protocol']
                port_num = int(port.attrib['portid'])
                try:
                    service = port.find('service').attrib['name']
                except (AttributeError, KeyError):
                    service = ''
                try:
                    product = port.find('service').attrib['product']
                except (AttributeError, KeyError):
                    product = ''
                try:
                    script_id = port.find('script').attrib['id']
                except (AttributeError, KeyError):
                    script_id = ''
                try:
                    script_output = port.find('script').attrib['output']
                except (AttributeError, KeyError):
                    script_output = ''
    
                # Create a list of the port data
                port_data = {'service': service,
                             'product': product,
                             'script_id': script_id,
                             'script_output': script_output}
    
                # Add the port data to the host data
                if proto in host_data[ip]:
                    host_data[ip][proto].setdefault(port_num, port_data)
                else:
                    host_data[ip].setdefault(proto, {port_num: port_data})

        trace_el = host.find('trace')
        if trace_el:
            trace_data = []
            hops = trace_el.findall('hop')
            for hop in hops:
                n = hop.attrib['ttl']
                rtr_ip = hop.attrib['ipaddr']
                try:
                    rtr_fqdn = hop.attrib['host']
                    if rtr_fqdn.endswith('in-addr.arpa'):
                        rtr_fqdn = ''
                except KeyError:
                    rtr_fqdn = ''

                trace_data.append({'n': n, 'rtr_ip': rtr_ip, 'rtr_fqdn': rtr_fqdn})

            host_data[ip].setdefault('trace', trace_data)

        res = {**res, **host_data}

    return res, nmap_args

def import_scan(filename, scantype, eid):
    isexternal = True if scantype == 'external' else False

    # a map of issue id to host/protocol/service
    service_map = {}
    # a map of host IP to ID
    host_map = {}

    data, arg_string = parse(filename)

    # compile a quick lookup dict for any existing data
    qry = db_getdict('select id, coalesce(ipv4, ipv6) as ip, os, rdns from hosts where engagement_id = %s', (eid,))
    if qry['success']:
        existing_hosts = qry['data']
    else:
        existing_hosts = {}
        logger.error('query failed')

    qry = db_getdict('select id, host_id, protocol, port, service, software, external, scan_uri_list\
                                 from services where host_id in (select id from hosts where engagement_id = %s)', (eid,))
    if qry['success']:
        existing_ports = qry['data']
    else:
        existing_ports = {}
        logger.error('query failed')

    existing_data = {}
    hostmap = {}
    for host in existing_hosts:
        ip = host['ip']
        existing_data.setdefault(ip, {'id': host['id'], 'os': host['os'], 'rdns': host['rdns']})
        hostmap.setdefault(host['id'], ip)

    for svc in existing_ports:
        host_id = svc['host_id']
        ip = hostmap[host_id]
        existing_data[ip].setdefault('services', {})
        existing_data[ip]['services'].setdefault(svc['protocol'], {})
        existing_data[ip]['services'][svc['protocol']][svc['port']] = {'sid': svc['id'],
                                                                       'service': svc['service'],
                                                                       'software': svc['software'],
                                                                       'scan_uri_list': svc['scan_uri_list'],
                                                                       'external': svc['external']}

    # store imported data
    conn = get_db()
    curs = conn.cursor()
    curs.execute('insert into nmap_scans(engagement_id, filename, arg_string, scan_type)\
                         values (%s, %s, %s, %s) returning id', (eid, filename, arg_string, scantype))
    nmap_id = str(curs.fetchone()[0])
    scan_uri = 'nmap/' + nmap_id

    for ip in data:
        rdns = data[ip]['hostnames'] if data[ip]['hostnames'] else None
        os = data[ip]['os'] if data[ip]['os'] else None

        if ip in existing_data:
            # if the ip is previously imported and we have nmap host data for it
            # update if empty only (nessus data more reliable)
            host_id = existing_data[ip]['id']
            if not existing_data[ip]['os'] and os:
                curs.execute('update hosts set os = %s where id = %s', (os, host_id))
            if not existing_data[ip]['rdns'] and rdns:
                if isinstance(rdns, list):
                    rdns_rec = None
                    for rec in rdns:
                        res = resolve(rec)
                        if res['ipv4'] or res['ipv6']:
                            rdns_rec = rec
                            break
                    # if no rdns records resolve, store the first from the list
                    if not rdns_rec:
                        rdns_rec = rdns[0]
                        logger.debug('no rdns resolves, adding ' + rdns_rec)
                        values.append(rdns_rec)

                curs.execute('update hosts set rdns = %s where id = %s', (rdns_rec, host_id))
                logger.debug(rdns_rec)
        else:
            # add a new entry in hosts table
            fields = []
            values = []
            if os:
                fields.append('os')
                values.append(os)
            if rdns:
                # smap (shodan based nmap lookalike) can return a list of rdns records
                # store the first one that actually resolves
                if isinstance(rdns, list):
                    for rec in rdns:
                        res = resolve(rec)
                        if res['ipv4'] or res['ipv6']:
                            fields.append('rdns')
                            values.append(rec)
                            break
                    # if no rdns records resolve, store the first from the list
                    if 'rdns' not in fields:
                        fields.append('rdns')
                        logger.debug('no rdns resolves, adding ' + rdns[0])
                        values.append(rdns[0])
                else:
                    fields.append('rdns')
                    values.append(rdns)

            ipv = 'ipv6' if is_ip(ip) == 6 else 'ipv4'
            if fields:
                sql = 'insert into hosts (engagement_id, ' + ipv + ', ' + ', '.join(fields) + ')\
                                         values (' + '%s, '*len(values) + ' %s, %s) returning id'
            else:
                sql = 'insert into hosts (engagement_id, ' + ipv + ') values (%s, %s) returning id'

            values = [eid, ip] + values
            logger.debug(repr(values))
            curs.execute(sql, tuple(values))
            host_id = curs.fetchone()[0]

        # add port info
        existing = False
        for protocol in ['tcp', 'udp']:
            if protocol in data[ip]:
                for port in data[ip][protocol]:
                    service = data[ip][protocol][port]['service']
                    software = data[ip][protocol][port]['product']

                    try:
                        sid = existing_data[ip]['services'][protocol][port]['sid']
                        logger.debug('existing service found ' + repr([ip, protocol, port, sid]))
                    except KeyError:
                        logger.debug('new service, storing ' + repr([host_id, ip, protocol, port]))
                        sid = None

                    if sid:
                        scan_uri_list = existing_data[ip]['services'][protocol][port]['scan_uri_list']
                        scan_uri_set = set(scan_uri_list.split(',')) if scan_uri_list else set()
                        scan_uri_set.add(scan_uri)
                        scan_uri_str = ','.join(scan_uri_set)
                        update_cols = ['scan_uri_list']
                        update_vals = [scan_uri_str]
                        if not existing_data[ip]['services'][protocol][port]['external'] and isexternal:
                            logger.debug('service found to be externally exposed as well, clobbering internal exposure')
                            update_cols.append('external')
                            update_vals.append(True)

                        if not existing_data[ip]['services'][protocol][port]['service']:
                            update_cols.append('service')
                            update_vals.append(service)

                        if not existing_data[ip]['services'][protocol][port]['software']:
                            update_cols.append('software')
                            update_vals.append(software)

                        update_vals.append(sid)
                        sql = get_pg_update_sql('services', update_cols, 'where id = %s')

                        curs.execute(sql, tuple(update_vals))
                    else:
                        curs.execute('insert into services (host_id, protocol, port, service, software, external, scan_uri_list)\
                                             values (%s, %s, %s, %s, %s, %s, %s)',
                                             (host_id, protocol, port, service, software, isexternal, scan_uri))
    
    conn.commit()
    curs.close()

    logger.debug('nmap scan imported')
    return {'error': False}

# execute as standalone
def main():
    filename = sys.argv[1]
    eng_id = sys.argv[2]
    scantype = sys.argv[3]
    import_scan(filename, eng_id, scantype)

if __name__ == "__main__":
    main()

