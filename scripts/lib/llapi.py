# Copyright (C) 2018 Timesys Corporation

import base64
import hashlib
import hmac
import json
import os
import ssl
import sys
import urllib.request
import urllib.parse
import urllib.error
from collections import OrderedDict


ll_url_default = 'https://linuxlink.timesys.com'
ll_url_env = os.getenv('LINUXLINK_SERVER')
LinuxLinkURL = ll_url_env if ll_url_env else ll_url_default
LinuxLinkSupportRoute = '/support'
LinuxLinkSupportURL = LinuxLinkURL + LinuxLinkSupportRoute
VigilesInfoURL = 'https://www.timesys.com/security/vulnerability-patch-notification/'


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
    dc_tokens = {
        'product': '',
        'folder': '',
    }

    try:
        with open(config_file, 'r') as f:
            cfg_info = json.load(f, encoding='utf-8')
    except (OSError, IOError, UnicodeDecodeError):
            pass
    except Exception:
        raise Exception("Unable to parse config file: %s" % config_file)
    else:
        dc_tokens['product'] = cfg_info.get('product', '').strip()
        dc_tokens['folder'] = cfg_info.get('folder', '').strip()

    return dc_tokens


def api_error_message(reason: str, param: str = '', extra: str = ''):
    from datetime import datetime

    err_dict = {
        '400': 'The LinuxLink request was empty or insufficient.',
        '403': 'Invalid credentials were sent to the LinuxLink Server.',
        '404': 'The specified LinuxLink URL does not exist.',
        '405': 'An incorrect LinuxLink URL was used.',
        '412': 'The manifest is malformed or missing fields.',
        '500': 'The Vigiles Service could not handle the request.',
        '503': 'The Vigiles Service is currently unavailable.',
        '504': 'The Vigiles Service is having an issue with the request/manifest.',
        'not-known': 'The Vigiles Service cannot be reached.',
        'timeout': 'Attempting to contact the server timed out.',
        'content': 'The LinuxLink response was empty or malformed.'
    }

    msg = [
        '',
        '%s' % ':\t'.join(['Vigiles Communication Error', err_dict.get(reason, reason)]),
        '',
        '%s' % ':\t'.join(['Current Time', datetime.utcnow().isoformat()]),
        '%s' % ':\t'.join(['Message', extra]),
        '%s' % ':\t'.join(['Parameter(s)', param]),
        '',
        'Please verify your Internet connection, firewall and proxy settings then try again.'
        '',
        '',
        '',
        'Information about LinuxLink and the Vigiles CheckCVEs Service can be found at:',
        '',
        '\t%s' % VigilesInfoURL,
        '',
        '',
        'If the issue persists, please contact LinuxLink support at:',
        '',
        '\t%s' % LinuxLinkSupportURL,
        '',
    ]

    print("%s" % '\n\t'.join(msg), file=sys.stderr)


def _do_api_call(request_dict, json_response):
    try:
        context = ssl._create_unverified_context()
    except AttributeError:
        context = None

    f = None
    response = None

    url = request_dict['url']
    err_reason = 'other'
    err_str = ''
    try:
        r = urllib.request.Request(**request_dict)
        f = urllib.request.urlopen(r, context=context) if context else urllib.request.urlopen(r)
        if not json_response:
            return f
        response = json.loads(f.read().decode('utf-8'), object_pairs_hook=OrderedDict)
    except urllib.error.HTTPError as e:
        err_reason = str(e.code)
        err_str = f.read().decode('utf-8') if f else str(e)
    except urllib.error.URLError as e:
        err_reason = 'not-known'
        err_str = ' '.join([ str(real_e) for real_e in e.args ])
    except (TypeError, UnicodeDecodeError):
        err_str = str(e)
        err_reason = 'content'
    except Exception as e:
        err_str = f.read().decode('utf-8') if f else str(e)
        for real_e in e.args:
            if isinstance(real_e, TimeoutError):
                err_reason = 'timeout'
                break

    if err_str:
        api_error_message(err_reason, url, err_str)
    return response


def api_get(email, key, resource, data_dict={}, json=True):
    data_dict['email'] = email
    msg = make_msg('GET', resource, data_dict)
    params = urllib.parse.urlencode(data_dict).encode('utf-8')
    request = {
        'headers': {
            'X-Auth-Signature': create_hmac(key, msg),
        },
        'url': LinuxLinkURL + resource + '?%s' % params,
    }
    return _do_api_call(request, json)


def api_post(email, key, resource, data_dict={}, json=True):
    data_dict['email'] = email
    msg = make_msg('POST', resource, data_dict)
    request = {
        'headers': {
            'X-Auth-Signature': create_hmac(key, msg),
        },
        'url': LinuxLinkURL + resource,
        'data': urllib.parse.urlencode(data_dict).encode('utf-8'),
    }
    return _do_api_call(request, json)
