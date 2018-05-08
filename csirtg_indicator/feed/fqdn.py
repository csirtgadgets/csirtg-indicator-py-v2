
PERM_WHITELIST = {
    'google.com',
    'yahoo.com',
    'facebook.com',
    'youtube.com',
    'netflix.com',
    'baidu.com',
    'wikipedia.org',
    'twitter.com',
    'qq.com',
    'taobao.com',
    'amazon.com',
    'live.com',
    'bing.com',
    'wordpress.com',
    'msn.com',
    'update.symantec.com',
    'weebly.com'
}


def match_whitelist(i, whitelist):
    bits = i.split('.')
    bits2 = list(bits)

    for d, b in enumerate(bits2):
        if '.'.join(bits) in whitelist:
            return True
        bits.pop(0)


def process(data, whitelist):
    if not isinstance(whitelist, set):
        whitelist = set(whitelist)

    # easier to read and understand than a sexy one-liner
    for i in data:
        if 'whitelist' in set(i['tags']):
            continue

        if i['indicator'] in PERM_WHITELIST or i['indicator'] in whitelist:
            return True

        if match_whitelist(i['indicator'], whitelist):
            continue

        yield i
