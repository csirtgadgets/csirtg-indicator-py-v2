from csirtg_indicator import Indicator

OK = (
    '128.205.1.1',
    'example.com',
    'https://csirtgadgets.com'
)

NOK = (
    '127.0.0.1',
    '172.31.3.1',
    'localhost.localdomain'
)


def test_geo_ok():
    for i in OK:
        assert Indicator(i, resolve_geo=True).asn is not None


def test_geo_nok():
    for i in NOK:
        assert Indicator(i, resolve_geo=True).asn is None
