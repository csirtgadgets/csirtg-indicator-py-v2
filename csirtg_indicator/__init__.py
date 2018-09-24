# -*- coding: utf-8 -*-
import sys

import json
import textwrap
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from datetime import datetime
import codecs
import pytricia
from base64 import b64encode
import logging
import uuid
import copy
import arrow

from .constants import PYVERSION, IPV4_PRIVATE_NETS, PROTOCOL_VERSION, FIELDS, FIELDS_TIME, LOG_FORMAT, VERSION, GEO, \
    PEERS, FQDN
from .utils import parse_timestamp, resolve_itype, is_subdomain, ipv4_normalize


if sys.version_info > (3,):
    from urllib.parse import urlparse
    basestring = (str, bytes)
else:
    from urlparse import urlparse

from pprint import pprint

IPV4_PRIVATE = pytricia.PyTricia()

for x in IPV4_PRIVATE_NETS:
    IPV4_PRIVATE[x] = True


class Indicator(object):

    def __init__(self, indicator=None, **kwargs):
        self.version = VERSION

        for k in FIELDS:
            if k in ['indicator', 'confidence', 'probability', 'count']:  # handle this at the end
                continue

            if kwargs.get(k) is None:
                v = None

                setattr(self, k, v)
                continue

            # set this at the end
            if k in FIELDS_TIME:
                continue

            if isinstance(kwargs[k], basestring):
                kwargs[k] = kwargs[k].lower()
                if k in ['tags', 'peers']:
                    kwargs[k] = kwargs[k].split(',')

            setattr(self, k, kwargs[k])

        for k in FIELDS_TIME:
            setattr(self, k, kwargs.get(k, None))

        self._indicator = None
        if indicator:
            self.indicator = indicator

        self._confidence = 0
        self.confidence = kwargs.get('confidence', 0)

        self._count = None
        self.count = kwargs.get('count', 1)

        self._probability = None
        self.probability = kwargs.get('probability', 0)

        if not self.uuid:
            self.uuid = str(uuid.uuid4())

        self.resolve_geo = kwargs.get('resolve_geo', GEO)
        self.resolve_peers = kwargs.get('resolve_peers', PEERS)
        self.resolve_fqdn = kwargs.get('resolve_fqdn', FQDN)

        if self.resolve_geo:
            self.geo_resolve()

        if self.resolve_peers:
            self.peers_resolve()

        if self.resolve_fqdn:
            self.fqdn_resolve()

    def copy(self, **kwargs):
        try:
            i = Indicator(**copy.deepcopy(self.__dict__()))

            for k in kwargs:
                setattr(i, k, kwargs[k])

            i.uuid = str(uuid.uuid4())
            if not isinstance(i.tags, list):
                i.tags = [i.tags]

            if not kwargs.get('last_at'):
                setattr(i, 'last_at', arrow.utcnow())

        except TypeError:
            i = None

        return i

    def is_fqdn(self):
        if self.itype == 'fqdn':
            return True

    def is_ip(self):
        if self.itype in ['ipv4', 'ipv6']:
            return True

    def is_ipv4(self):
        if self.itype == 'ipv4':
            return True

    def is_ipv6(self):
        if self.itype == 'ipv6':
            return True

    def is_url(self):
        if self.itype == 'url':
            return True

    def is_hash(self):
        if self.itype in ['md5', 'sha1', 'sha256', 'sha512']:
            return True

    def is_email(self):
        if self.itype == 'email':
            return True

    def spamhaus(self):
        from csirtg_indicator.utils.spamhaus import ip, fqdn
        if self.is_ip():
            return ip.process(self, resolve_geo=self.resolve_geo)
        elif self.is_fqdn():
            return fqdn.process(self, resolve_geo=self.resolve_geo)
        else:
            return None

    @property
    def indicator(self):
        return self.__indicator

    @indicator.setter
    def indicator(self, i):
        if not i:
            self._indicator = None
            return

        if PYVERSION == 2:
            try:
                i = codecs.unicode_escape_encode(i.decode('utf-8'))[0]
            except Exception:
                i = codecs.unicode_escape_encode(i.encode('utf-8', 'ignore').decode('utf-8'))[0]

        i = i.lower()
        self.itype = resolve_itype(i)
        self._indicator = i

        if self.itype == 'url':
            u = urlparse(self._indicator)
            self._indicator = u.geturl().rstrip('/').lower()

        if self.itype == 'ipv4':
            self._indicator = ipv4_normalize(self._indicator)

        if self.mask and (self.itype in ['ipv4', 'ipv6']):
            self._indicator = '{}/{}'.format(self._indicator, int(self.mask))
            self.mask = None

    def _time_setter(self, v):
        if not v:
            return

        if isinstance(v, datetime):
            return v
        else:
            return parse_timestamp(v).to('utc').datetime

    @indicator.getter
    def indicator(self):
        return self._indicator

    @property
    def confidence(self):
        return self._confidence

    @property
    def reported_at(self):
        return self._reported_at

    @reported_at.getter
    def reported_at(self):
        return self._reported_at

    @reported_at.setter
    def reported_at(self, v):
        self._reported_at = self._time_setter(v)

    @property
    def last_at(self):
        return self._last_at

    @last_at.getter
    def last_at(self):
        return self._last_at

    @last_at.setter
    def last_at(self, v):
        self._last_at = self._time_setter(v)

    @property
    def first_at(self):
        return self._first_at

    @first_at.getter
    def first_at(self):
        return self._first_at

    @first_at.setter
    def first_at(self, v):
        self._first_at = self._time_setter(v)

    @confidence.setter
    def confidence(self, v):
        self._confidence = float(v)

    @confidence.getter
    def confidence(self):
        return self._confidence

    @property
    def count(self):
        return self._count

    @count.setter
    def count(self, v):
        self._count = int(v)

    @count.getter
    def count(self):
        return self._count

    def get(self, v, default=None):
        v1 = getattr(self, v)
        if v1:
            return v1
        return default

    def geo_resolve(self):
        from csirtg_indicator.utils.geo import process
        process(self)

    def peers_resolve(self):
        from csirtg_indicator.utils.network import resolve_peers
        resolve_peers(self)

    def fqdn(self):
        if self.itype == 'fqdn':
            return self.indicator

        if self.itype == 'url':
            from .utils import url_to_fqdn
            return url_to_fqdn(self.indicator)

    def fqdn_resolve(self):
        if self.itype not in ['url', 'fqdn']:
            return

        from csirtg_indicator.utils.network import resolve_fqdn, resolve_ns, resolve_url

        d = self.indicator
        if self.itype == 'url':
            d = resolve_url(self.indicator)
            if not d:
                return

        r = resolve_fqdn(d)
        if not r or r in ["", "localhost"]:
            return

        if not isinstance(r, list):
            r = [r]

        setattr(self, 'rdata', r)
        setattr(self, 'rtype', 'A')

        r = resolve_ns(d, t='NS')
        if not r or r in ["", "localhost"]:
            return

        r = [str(rr) for rr in r]
        setattr(self, 'ns', r)

        r = resolve_ns(d, t='MX')
        if not r or r in ["", "localhost"]:
            return

        r = [str(rr) for rr in r]
        setattr(self, 'mx', r)

        r = resolve_ns(d, t='CNAME')
        if not r or r in ["", "localhost"]:
            return

        r = [str(rr) for rr in r]
        setattr(self, 'cname', r)

    def is_private(self):
        if not self.itype:
            return False

        if self.itype != 'ipv4':
            return False

        if IPV4_PRIVATE.get(str(self.indicator)):
            return True

    def is_subdomain(self):
        return is_subdomain(self.indicator)

    def ipv4_to_prefix(self, n=24):
        prefix = self.indicator.split('.')
        prefix = prefix[:3]
        prefix.append('0/%i' % n)
        return '.'.join(prefix)

    def csirtg(self):
        try:
            from csirtgsdk.client import Client
            from csirtgsdk.search import Search
        except ImportError:
            print('')
            print('The csirtg function requires the csirtgsdk')
            print('$ pip install csirtgsdk')
            print('$ export CSIRTG_TOKEN=1234...')
            print('')
            raise SystemExit

        return Search(Client()).search(self.indicator, limit=5)

    def cif(self):
        try:
            from cifsdk.client.http import HTTP as Client
        except ImportError:
            print('')
            print('The cif function requires the cifsdk>=4.0')
            print('$ pip install https://github.com/csirtgadgets/verbose-robot-sdk-py/archive/master.zip')
            print('$ export CIF_TOKEN=1234...')
            print('')
            raise SystemExit

        return Client().search({'q': self.indicator, 'limit': 25})

    def farsight(self):
        if self.itype != 'ipv4':
            raise TypeError('%s is not supported' % self.itype)

        try:
            from csirtg_dnsdb.client import Client
        except ImportError:
            print('')
            print('The csirtg function requires the csirtg_dnsdb client')
            print('https://github.com/csirtgadgets/dnsdb-py')
            print('$ pip install csirtg_dnsdb')
            print('$ export FARSIGHT_TOKEN=1234...')
            print('')
            raise SystemExit

        return Client().search(self.indicator)

    def predict(self):
        if self.itype not in ['url', 'fqdn', 'ipv4']:
            raise TypeError('%s is not supported' % self.itype)

        try:
            if self.itype == 'ipv4':
                from .utils.predict import predict_ips
                p = predict_ips(self)
                return [p[0].probability]

            if self.itype == 'fqdn':
                from .utils.predict import predict_fqdns
                p = predict_fqdns(self)
                return [p[0].probability]

            if self.itype == 'url':
                from .utils.predict import predict_urls
                p = predict_urls(self)
                return [p[0].probability]

        except ImportError:
            print('')
            print('This requires the csirtg_ipsml_tf, csirtg_domainsml_tf and csirtg_urlsml_tf frameworks')
            print('https://csirtgadgets.com/?tag=machine-learning')
            print('$ pip install csirtg_ipsml_tf csirtg_domainsml_tf csirtg_urlsml_tf')
            print('')
            raise SystemExit

    def format_keys(self):
        d = self.__dict__()
        for k in d:
            if PYVERSION == 2:
                if not isinstance(d[k], unicode):
                    continue
            else:
                if not isinstance(d[k], str):
                    continue

            if '{' not in d[k]:
                continue

            try:
                d[k] = d[k].format(**d)
            except (KeyError, ValueError, IndexError):
                pass

        return Indicator(**d)

    def __dict__(self):
        s = str(self)
        return json.loads(s)

    def __repr__(self):
        i = {}

        if self.resolve_geo and not self.asn:
            self.geo_resolve()

        for k in FIELDS:

            v = getattr(self, k)
            if not v:
                continue

            if k == 'message':
                if PYVERSION == 2:
                    v = codecs.unicode_escape_encode(v.decode('utf-8'))[0]
                else:
                    v = v.encode('utf-8')

                v = b64encode(v).decode('utf-8')

            if k in FIELDS_TIME and isinstance(v, datetime):
                v = v.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            if isinstance(v, basestring):
                if k is not 'message' and not k.endswith('_at'):
                    v = v.lower()

            if k == 'confidence':
                v = float(v)

            i[k] = v

        sort_keys = False
        indent = None
        if logging.getLogger('').getEffectiveLevel() == logging.DEBUG:
            sort_keys = True
            indent = 4
        try:
            return json.dumps(i, indent=indent, sort_keys=sort_keys, separators=(',', ': '))
        except UnicodeDecodeError as e:
            i['asn_desc'] = unicode(i['asn_desc'].decode('latin-1'))
            return json.dumps(i, indent=indent, sort_keys=sort_keys, separators=(',', ': '))

    def __eq__(self, other):
        d1 = self.__dict__()
        d2 = other.__dict__()
        return d1 == d2


def main():
    p = ArgumentParser(
        description=textwrap.dedent('''\
             Env Variables:
                CSIRTG_INDICATOR_TLP
                CSIRTG_INDICATOR_GROUP

            example usage:
                $ csirtg-indicator -d
            '''),
        formatter_class=RawDescriptionHelpFormatter,
        prog='csirtg-indicator'
    )

    p.add_argument('-d', '--debug', dest='debug', action="store_true")
    p.add_argument('-V', '--version', action='version', version=VERSION)

    p.add_argument('--group', help="specify group")
    p.add_argument('--indicator', '-i', help="specify indicator")
    p.add_argument('--tlp', help='specify tlp', default='green')
    p.add_argument('--tags', help='specify tags')

    args = p.parse_args()

    loglevel = logging.getLevelName('INFO')

    if args.debug:
        loglevel = logging.DEBUG

    console = logging.StreamHandler()
    logging.getLogger('').setLevel(loglevel)
    console.setFormatter(logging.Formatter(LOG_FORMAT))
    logging.getLogger('').addHandler(console)

    i = Indicator(indicator=args.indicator, tlp=args.tlp, tags=args.tags)

    print(i)


if __name__ == '__main__':
    main()
