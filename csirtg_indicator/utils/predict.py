
try:
    from csirtg_urlsml_tf import predict as predict_url
    from csirtg_domainsml_tf import predict as predict_fqdn
    from csirtg_ipsml_tf import predict as predict_ip
    from csirtg_ipsml_tf.utils import extract_features as extract_features_ip

except ImportError:

    print('')
    print('This requires the csirtg_ipsml_tf, csirtg_domainsml_tf and csirtg_urlsml_tf frameworks')
    print('https://csirtgadgets.com/?tag=machine-learningy')
    print('$ pip install csirtg_ipsml_tf csirtg_domainsml_tf csirtg_urlsml_tf')
    print('')
    raise ImportError


def predict_urls(indicators):
    if not isinstance(indicators, list):
        indicators = [indicators]

    urls = [(i.indicator, idx) for idx, i in enumerate(indicators) if i.itype == 'url']

    predict = predict_url([u[0] for u in urls])

    for idx, u in enumerate(urls):
        indicators[u[1]].probability = predict[idx][0]

    return indicators


def predict_fqdns(indicators):
    if not isinstance(indicators, list):
        indicators = [indicators]

    urls = [(i.indicator, idx) for idx, i in enumerate(indicators) if i.itype == 'fqdn']

    predict = predict_fqdn([u[0] for u in urls])

    for idx, u in enumerate(urls):
        indicators[u[1]].probability = predict[idx][0]

    return indicators


def predict_ips(indicators):
    if not isinstance(indicators, list):
        indicators = [indicators]

    ips = [(i, idx) for idx, i in enumerate(indicators) if i.itype == 'ipv4' and not i.probability]

    if len(ips) == 0:
        return indicators

    ips_feats = []
    for i in ips:
        f = list(extract_features_ip(i[0].indicator, i[0].reported_at))
        ips_feats.append(f[0])

    predict = predict_ip([ips_feats])

    for idx, u in enumerate(ips):
        indicators[u[1]].probability = predict[idx][0]

    return indicators
