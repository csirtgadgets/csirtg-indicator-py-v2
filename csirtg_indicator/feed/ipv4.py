
import pytricia
import ipaddress

from pprint import pprint

PERM_WHITELIST = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "192.0.2.0/24",
    "224.0.0.0/4",
    "240.0.0.0/5",
    "248.0.0.0/5",
]

LARGEST_PREFIX = '8'


def _normalize(i):
    bits = i.split('.')

    rv = []
    for b in bits:
        if len(b) > 1 and b.startswith('0') and not b.startswith('0/'):
            b = b[1:]
        rv.append(b)

    i = '.'.join(rv)

    try:
        i = unicode(i) #py2
    except Exception:
        pass

    return i


# https://github.com/jsommers/pytricia
def process(data=[], whitelist=[]):
    wl = pytricia.PyTricia()
    for x in PERM_WHITELIST:
        wl[x] = True

    for y in whitelist:
        y = str(_normalize(y['indicator']))
        if '/' not in y:  # weird bug work-around it'll insert 172.16.1.60 with a /0 at the end??
            y = '{}/32'.format(y)

        wl[y] = True

    for i in data:
        if 'whitelist' in set(i['tags']):
            continue

        i['indicator'] = _normalize(i['indicator'])

        try:
            ipaddress.ip_network(i['indicator'])

        except ValueError as e:
            print('skipping invalid address: %s' % i['indicator'])

        if str(i['indicator']) not in wl:
            yield i
