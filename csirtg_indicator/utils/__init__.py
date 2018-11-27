from pprint import pprint
import os, socket
import re
import ipaddress
from ..constants import PYVERSION, RE_IPV4, RE_IPV4_CIDR, RE_IPV4_PADDING, RE_IPV6, RE_FQDN, RE_ASN, RE_EMAIL, \
    RE_HASH, RE_URI_SCHEMES

from .ip import is_ipv4, is_ipv4_cidr, is_ipv6, is_ip

from .ztime import parse_timestamp

try:
    # py3
    from urllib.parse import urlparse
    import importlib
except ImportError:
    # py2
    from urlparse import urlparse


def ipv4_normalize(i):
    return RE_IPV4_PADDING.sub(r'\1\2', i)


def load_plugin(path, plugin):
    path = os.path.join(path, ('%s.py' % plugin))
    spec = importlib.util.spec_from_file_location(path, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def is_valid(i):
    try:
        resolve_itype(i)
        return True
    except TypeError as e:
        return False


def is_hash(s):
    for h in RE_HASH:
        if re.match(RE_HASH[h], s):
            return h


def is_email(s):
    if re.match(RE_EMAIL, s):
        return True


def is_asn(s):
    if re.match(RE_ASN, s):
        return True


def is_fqdn(s):
    if RE_FQDN.match(s):
        return True


def is_url(s):
    u = urlparse(s)

    if not u:
        return

    if not re.match(RE_URI_SCHEMES, str(u.scheme)):
        return

    u = u.hostname

    if is_ip(u) or is_fqdn(u):
        return True

    if ':' in u:  # 192.168.1.1:81
        u1 = u.split(':')[0]
        if is_ipv4(u1) or is_fqdn(u1):
            return True


def is_url_broken(s):
    if PYVERSION == 2:
        s = s.encode('utf-8')

    u = urlparse('{}{}'.format('http://', s))

    if not re.match(RE_URI_SCHEMES, u.scheme):
        return

    if is_fqdn(u.hostname) or is_ipv4(u.hostname) or is_ipv6(u.hostname):
        return True


def resolve_itype(indicator, test_broken=False):
    if test_broken and is_url_broken(indicator):
        return 'broken_url'

    elif is_url(indicator):
        return 'url'

    elif is_hash(indicator):
        return is_hash(indicator)

    elif is_ipv4(indicator) or is_ipv4_cidr(indicator):
        return 'ipv4'

    elif is_ipv6(indicator):
        return 'ipv6'

    elif is_email(indicator):
        return 'email'

    elif is_fqdn(indicator):
        return 'fqdn'

    elif is_asn(indicator):
        return 'asn'

    try:
        error = 'unknown itype for "{}"'.format(indicator)
    except UnicodeEncodeError:
        error = 'unknown itype for "{}"'.format(indicator.encode('utf-8'))

    raise TypeError(error)


def normalize_itype(i, itype=None):
    try:
        if resolve_itype(i['indicator']):
            return i
    except TypeError:
        pass

    i = _normalize_url(i)
    return i


def is_subdomain(i):
    itype = resolve_itype(i)
    if itype is not 'fqdn':
        return

    bits = i.split('.')
    if len(bits) > 2:
        bits.pop(0)
        return '.'.join(bits)


def is_ipv4_net(i):
    try:
        if resolve_itype(i) != 'ipv4':
            return False
    except TypeError:
        return False

    if not re.match(RE_IPV4_CIDR, i):
        return False

    if PYVERSION == 2:
        i = unicode(i)

    try:
        ipaddress.ip_network(i)
        return True
    except ValueError:
        return False


def _normalize_url(i):
    if resolve_itype(i['indicator'], test_broken=True) == 'broken_url':
        if PYVERSION == 2:
            i['indicator'] = i['indicator'].encode('utf-8')
        i['indicator'] = '{}{}'.format('http://', i['indicator'])

    return i


def url_to_fqdn(u):
    u = urlparse(u)
    return u.hostname


def list_to_csv(mylist):
    if len(mylist) > 0 and isinstance(mylist[0], dict):
        mylist = ''
    else:
        mylist = u','.join(mylist)

    return mylist
