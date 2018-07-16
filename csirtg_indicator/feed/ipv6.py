import pytricia
import ipaddress

PERM_WHITELIST = [
    ## TODO -- more
    # http://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml
    # v6
    'FF01:0:0:0:0:0:0:1',
    'FF01:0:0:0:0:0:0:2',
]


def process(data, whitelist=[]):
    wl = pytricia.PyTricia()

    [wl.insert(x, True) for x in PERM_WHITELIST]

    [wl.insert(str(y['indicator']), True) for y in whitelist]

    # [(yield i) for i in data if not 'whitelist' in set(i['tags']) and str(i['indicator']) not in wl]

    for i in data:
        if 'whitelist' in set(i['tags']):
            continue

        try:
            ipaddress.ip_network(i['indicator'])

        except ValueError as e:
            print('skipping invalid address: %s' % i['indicator'])

        if str(i['indicator']) not in wl:
            yield i
