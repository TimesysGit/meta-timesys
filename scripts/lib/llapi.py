# Copyright (C) 2018 Timesys Corporation

import base64
import hashlib
import hmac
import json
import ssl
import urllib.request
import urllib.parse
import urllib.error
from collections import OrderedDict

LINUXLINK_SERVER = 'https://linuxlink.timesys.com'


def make_msg(method, resource, data):
    s = '&'.join(['%s=%s' % (k,v) for k,v in sorted(data.items())])
    return method.upper() + resource + s


def create_hmac(key, msg):
    if key is not None:
        key = key.encode('utf-8')
    else:
        key = 'None'.encode('utf-8')
    msg = msg.encode('utf-8', 'backslashreplace')
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

# This raises an error if it can't read or decode a file that's present, but
# leaves it to the caller to decide what to do with empty values.
def read_dashboard_config(config_file):
    try:
        with open(config_file, 'r') as f:
            cfg_info = json.load(f, encoding='utf-8')
    except (OSError, IOError, UnicodeDecodeError):
            product = None
    except Exception:
        raise Exception("Unable to parse config file: %s" % config_file)
    else:
        product = cfg_info.get('product', '').strip()

    return product


def _do_api_call(request_dict, json_response):
    try:
        context = ssl._create_unverified_context()
    except AttributeError:
        context = None

    try:
        r = urllib.request.Request(**request_dict)
        f = urllib.request.urlopen(r, context=context) if context else urllib.request.urlopen(r)
    except urllib.error.HTTPError as e:
        raise Exception('LinuxLink server returned status: %s' % e.code)
    except Exception as e:
        raise Exception('Unable to connect to LinuxLink server: %s' % e)

    if not json_response:
        return f

    response = f.read().decode('utf-8')
    return json.loads(response, object_pairs_hook=OrderedDict)


def api_get(email, key, resource, data_dict={}, json=True):
    data_dict['email'] = email
    msg = make_msg('GET', resource, data_dict)
    params = urllib.parse.urlencode(data_dict).encode('utf-8')
    request = {
        'headers': {
            'X-Auth-Signature': create_hmac(key, msg),
        },
        'url': LINUXLINK_SERVER + resource + '?%s' % params,
    }
    return _do_api_call(request, json)


def api_post(email, key, resource, data_dict={}, json=True):
    data_dict['email'] = email
    msg = make_msg('POST', resource, data_dict)
    request = {
        'headers': {
            'X-Auth-Signature': create_hmac(key, msg),
        },
        'url': LINUXLINK_SERVER + resource,
        'data': urllib.parse.urlencode(data_dict).encode('utf-8'),
    }
    return _do_api_call(request, json)
