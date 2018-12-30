
from csirtg_indicator.utils import url_to_fqdn


class UtilsMixin(object):
    itype = None
    indicator = None

    def fqdn(self):
        if self.itype == 'fqdn':
            return self.indicator

        if self.itype != 'url':
            return

        return url_to_fqdn(self.indicator)

    def ipv4_to_prefix(self, n=24):
        prefix = self.indicator.split('.')
        prefix = prefix[:3]
        prefix.append('0/%i' % n)
        return '.'.join(prefix)
