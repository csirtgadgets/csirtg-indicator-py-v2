from .fqdn import process as process_fqdn
from .ipv4 import process as process_ipv4
from .ipv6 import process as process_ipv6


def process(data, whitelist, itype=None):
    if itype == 'ipv4':
        return process_ipv4(data, whitelist)

    if itype == 'ipv6':
        return process_ipv6(data, whitelist)

    if itype == 'fqdn':
        return process_ipv6(data, whitelist)

    # this is left for specific itypes, hashes, urls, things that are generally not a range
    # yield the indicator if whitelist isn't in it's tag, and it's not in the whitelist
    [(yield x) for x in data if 'whitelist' not in set(x['tags']) and x['indicator'] not in set(whitelist)]
