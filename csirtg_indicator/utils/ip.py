import ipaddress
import socket
import re

from csirtg_indicator.constants import RE_IPV4, RE_IPV4_CIDR


def is_valid_ip(i):
    try:
        ipaddress.ip_network(i)
    except ValueError as e:
        return False

    return True


def is_ipv6(s):
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except socket.error:
        pass
    except UnicodeEncodeError:
        return False

    try:
        # py2
        s = unicode(s)
    except UnicodeDecodeError:
        return False
    except NameError:
        pass

    try:
        ipaddress.IPv6Network(s)
        return True
    except ipaddress.AddressValueError:
        pass


def is_ipv4(s):

    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except socket.error:
        pass
    except UnicodeEncodeError:
        return False

    if re.match(RE_IPV4, s):
        return True


def is_ipv4_cidr(s):
    if not re.match(RE_IPV4_CIDR, s):
        return False

    try:
        # py2
        s = unicode(s)
    except UnicodeDecodeError:
        return False
    except NameError:
        pass

    try:
        ipaddress.ip_network(s)
        return True
    except ValueError as e:
        return False


