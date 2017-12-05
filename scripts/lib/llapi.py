# Copyright (C) 2007-2017 Timesys Corporation

import base64
import hashlib
import hmac
import json
import ssl
import urllib
import urllib2

LINUXLINK_SERVER = 'https://linuxlink.timesys.com'


def make_msg(method, resource, data):
    s = '&'.join(['%s=%s' % (k,v) for k,v in sorted(data.items())])
    return method.upper() + resource + s


def create_hmac(key, msg):
    sig = hmac.new(key, msg=msg, digestmod=hashlib.sha256).digest()
    return base64.b64encode(sig)


# This raises an error if it can't read or decode a file that's present, but
# leaves it to the caller to decide what to do with empty values.
def read_keyfile(key_file):
    try:
        with open(key_file, 'r') as f:
            key_info = json.load(f, encoding='utf-8')
    except (OSError, IOError, UnicodeDecodeError):
            email, key = (None, None)
    except Exception:
        raise Exception("Unable to parse key file: %s" % key_file)
    else:
        email = key_info.get('email', '').strip()
        key = key_info.get('key', '').strip()

    return (email, key)


def _do_api_call(request_dict, json_response):
    try:
        context = ssl._create_unverified_context()
    except AttributeError:
        context = None

    try:
        r = urllib2.Request(**request_dict)
        f = urllib2.urlopen(r, context=context) if context else urllib2.urlopen(r)
    except urllib2.HTTPError as e:
        raise Exception('LinuxLink server returned status: %s' % e.code)
    except Exception as e:
        raise Exception('Unable to connect to LinuxLink server: %s' % e)

    if not json_response:
        return f
    return json.loads(f.read())


def api_get(email, key, resource, data_dict={}, json=True):
    data_dict['email'] = email
    msg = make_msg('GET', resource, data_dict)
    request = {
        'headers': {
            'X-Auth-Signature': create_hmac(str(key), msg),
        },
        'url': LINUXLINK_SERVER + resource + '?%s' % urllib.urlencode(data_dict),
    }
    return _do_api_call(request, json)


def api_post(email, key, resource, data_dict={}, json=True):
    data_dict['email'] = email
    msg = make_msg('POST', resource, data_dict)
    request = {
        'headers': {
            'X-Auth-Signature': create_hmac(str(key), msg),
        },
        'url': LINUXLINK_SERVER + resource,
        'data': urllib.urlencode(data_dict)
    }
    return _do_api_call(request, json)
