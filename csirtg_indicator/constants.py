from ._version import get_versions
__version__ = get_versions()['version']
VERSION = __version__
del get_versions

import sys, os, re

PYVERSION = 2
if sys.version_info > (3,):
    PYVERSION = 3

LOG_FORMAT = '%(asctime)s - %(levelname)s - %(name)s[%(lineno)s] - %(message)s'
PROTOCOL_VERSION = '2.0.0-a.1'

COLUMNS = ['tlp', 'group', 'reported_at', 'indicator', 'asn', 'cc', 'first_at', 'last_at', 'count', 'tags',
           'description', 'confidence', 'rdata', 'provider', 'probability', 'reference']

MAX_FIELD_SIZE = 30

IPV4_PRIVATE_NETS = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.2.0/24",
    "224.0.0.0/4",
    "240.0.0.0/5",
    "248.0.0.0/5"
]


FIELDS_CORE = [
    'indicator', 'itype', 'tlp', 'provider', 'group', 'tlp', 'provider', 'count', 'message', 'tags', 'confidence',
    'description', 'version', 'uuid', 'probability'
]

FIELDS_TIME = [
    'first_at', 'last_at', 'reported_at'
]

FIELDS_META = [
    'application', 'reference', 'reference_tlp', 'data'
]

FIELDS_GEO = [
    'cc', 'latitude', 'timezone', 'longitude', 'city', 'region'
]

FIELDS_IP = [
    'portlist', 'protocol', 'asn', 'asn_desc', 'dest', 'dest_portlist', 'mask', 'rdata', 'peers'
]

FIELDS_FQDN = [
    'ns', 'mx', 'cname'
]

FIELDS = FIELDS_CORE + FIELDS_GEO + FIELDS_META + FIELDS_IP + FIELDS_TIME + FIELDS_FQDN


# regexes

RE_IPV4 = re.compile('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(\d{1,3})$')
RE_IPV4_CIDR = re.compile('^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/\d{1,2})$')

# http://stackoverflow.com/a/17871737
RE_IPV6 = re.compile('(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')

# http://goo.gl/Cztyn2 -- probably needs more work
# http://stackoverflow.com/a/26987741/7205341
# ^((xn--)?(--)?[a-zA-Z0-9-_@]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}(--p1ai)?$
#RE_FQDN = re.compile('^((?!-))(xn--)?[a-z0-9][a-z0-9-_\.]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$')
# http://stackoverflow.com/questions/14402407/maximum-length-of-a-domain-name-without-the-http-www-com-parts
RE_FQDN = re.compile('^((?!-))(xn--)?[a-z0-9][a-z0-9-_\.]{0,245}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$')
RE_URI_SCHEMES = re.compile('^(https?|ftp)$')
RE_EMAIL = re.compile('^[_a-z0-9-\!\#\$\%\&\'\*\+\-\/\=\?\^\_\`\{\|\}\~]+(\.[_a-z0-9-\!\#\$\%\&\'\*\+\-\/\=\?\^\_\`\{\|\}\~]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$')
RE_ASN = re.compile('^(AS|as)[0-9]{1,6}$')

RE_HASH = {
    'uuid': re.compile('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'),
    'md5': re.compile('^[a-fA-F0-9]{32}$'),
    'sha1': re.compile('^[a-fA-F0-9]{40}$'),
    'sha256': re.compile('^[a-fA-F0-9]{64}$'),
    'sha512': re.compile('^[a-fA-F0-9]{128}$'),
}

RE_IPV4_PADDING = re.compile(r"(^|\.)0+([^/.])")


GEO = os.getenv('CSIRTG_INDICATOR_GEO', False)
if GEO == '1':
    GEO = True

PEERS = os.getenv('CSIRTG_INDICATOR_PEERS', False)
if PEERS == '1':
    PEERS = True

FQDN = os.getenv('CSIRTG_INDICATORS_RESOLVE_FQDN', False)
if FQDN == '1':
    FQDN = True