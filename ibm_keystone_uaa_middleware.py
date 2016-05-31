# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_log import log
from oslo_config import cfg
from keystone.common import wsgi
from keystone import exception
from keystone.common import dependency
import requests
import json
import base64
import re
import ConfigParser
import urllib

LOG = log.getLogger(__name__)
CONF = cfg.CONF


# Environment variable used to pass the request context
CONTEXT_ENV = wsgi.CONTEXT_ENV


HEADER = {}
BM_HEADER = {}

UAA_ENV_LIST = ['https://uaa.ng.bluemix.net/oauth/token',
                'https://uaa.eu-gb.bluemix.net/oauth/token',
                'https://uaa.stage1.ng.bluemix.net/oauth/token',
                'https://uaa.stage1.eu-gb.bluemix.net/oauth/token',
                'https://uaa.dys0.bluemix.net/oauth/token',
                'https://uaa.w3ibm.bluemix.net/oauth/token']

# Environment variable used to pass the request params
#PARAMS_ENV = wsgi.PARAMS_ENV

def load_config(section, key, data_type):
    """
    Reads value from config file and returns
    a value for the key received.

    :parm section: Config section
    :parm key: Key name
    :parm dataType: Datatype
    :type section: string
    :type key: string
    :type dataType: string
    """
    config = ConfigParser.RawConfigParser()
    filepath = "/etc/keystone/keystone.conf"
    try:
        with open(filepath):
            pass
    except IOError:
        filepath = 'keystone.conf'
    config.read(filepath)
    if data_type == 'int':
        value = config.getint(section, key)
    elif data_type == 'bool':
        value = config.getboolean(section, key)
    else:
        value = config.get(section, key)
    return value

# IDAAS Config

IDAAS = load_config('idaas','token_endpoint','string')
IDAAS_INTROS = load_config('idaas','introspect','string')
CLIENTID = load_config('idaas','client_id','string')
SECRET = load_config('idaas','secret','string')



@dependency.requires('identity_api', 'resource_api')
class UAAAuthMiddleware(wsgi.Middleware):

    def __init__(self, *args, **kwargs):
        super(UAAAuthMiddleware, self).__init__(*args, **kwargs)

    def _domain_lookup(self, request):
        """
        Method to return domain name
        """
        body = json.loads(request.body)
        try:
            domain = body['auth']['identity']['password'][
                'user']['domain'].get('name')
        except Exception:
            domain = None
        if domain is None:
            domain = self._domain_lookup_by_id(request)
        return domain

    def _domain_lookup_by_id(self, request):
        """
        If domain name has not been provided theis method
        will lookup for domain id to obtain domain name
        """
        body = json.loads(request.body)
        try:
            domain = body['auth']['identity']['password'][
                'user']['domain'].get('id')
        except Exception:
            domain = None
        if domain is not None:
            domain = self._get_domain_name_by_id(domain)
        return domain

    def _get_domain_name_by_id(self, id):
        """
        Get domain name by domain id
        """
        try:
            domain_ref = self.resource_api.get_domain(id)
        except Exception:
            raise exception.Unauthorized(
                'Invalid Domain id passed' + ' ' + id)
        LOG.debug(domain_ref['name'])
        return domain_ref['name']

    def _decode_base64(self, uaa_data):
        """
        Decode base64, padding being optional.
        """
        padding = 4 - (len(uaa_data) % 4)
        if padding:
            uaa_data += b'='* padding
        return base64.b64decode(uaa_data)


    def _change_method_name(self, body):
        """
        Searches for password key and replace that with
        external
        """
        new_body = {}
        for k, v in body.iteritems():
            if isinstance(v, dict):
                v = self._change_method_name(v)
            new_body[k.replace("password","external")] = v
        return new_body

    def _build_payload(self, domain, request):

        body = json.loads(request.body)
        payload = {}
        payload['auth'] = {}
        payload['auth']['identity'] = {}
        payload['auth']['identity']['methods'] = []
        payload['auth']['identity']['methods'].append("external")

        sub_payload = {}
        sub_payload['user'] = {}
        sub_payload['user']['name'] = request.environ['REMOTE_USER']
        sub_payload['user']['password'] = "default"
        payload['auth']['identity']['external'] = sub_payload
        payload['auth']['scope'] = {}
        payload['auth']['scope'] = body['auth']['scope']
        request.environ['REMOTE_DOMAIN'] = domain
        request.body = json.dumps(payload, indent=True)


    def process_request(self, request):

        uaa_token = request.headers.get("X-UAA-Token")
        idaas_access_token = request.headers.get("X-Access-Token")
        idaas_id_token = request.headers.get("X-ID-Token")
        domain = request.headers.get("X-User-domain")
        if (uaa_token or idaas_access_token and
            request.environ['PATH_INFO'] == '/auth/tokens' and
            len(request.body) > 0):
            if not (request.headers.get("Content-type") or
                request.headers.get("content-type") or
                request.headers.get("Content-Type")):
                raise exception.Unauthorized(
                    "Please provide Content-Type")
            if domain is None:
                raise exception.Unauthorized(
                    "X-User-domain not mentioned")
            if uaa_token:
                uaa_token_parse = uaa_token.split('.')
                decoded_uaa_str = self._decode_base64(uaa_token_parse[1])
                decode_uaa = json.loads(decoded_uaa_str)
                uaa_token_url = decode_uaa['iss']
                if uaa_token_url not in UAA_ENV_LIST:
                    LOG.debug('%s env not supported', uaa_token_url)
                    raise exception.Unauthorized("UAA environment not supported")
                reg_compile = re.compile("oauth")
                match = reg_compile.search(uaa_token_url)
                UAA = uaa_token_url[:match.start()]
                url = UAA + 'userinfo'
                HEADER['Authorization'] = uaa_token
                try:
                    response = requests.get(url,
                                            headers=HEADER,
                                            verify=False)
                    if response.status_code != 200:
                        LOG.warning('Invalid Auth token received')
                        raise exception.Unauthorized("Invalid user")
                    result = response.json()
                    username =  result.get('user_name')
                    request.environ['REMOTE_USER'] = str(username)
                    self._build_payload(domain, request)
                except Exception as e:
                    LOG.debug(e)
                    LOG.warning('Invalid Auth token received')
                    raise exception.Unauthorized("Invalid user")
            else:
                payload = {}
                payload['token'] = idaas_access_token
                try:
                    response = requests.post(IDAAS_INTROS,
                                             auth=(CLIENTID, SECRET),
                                             data=payload)
                    result = response.json()
                    LOG.debug(result)
                    if not result.get('sub'):
                        LOG.warning('Invalid Auth token received')
                        raise exception.Unauthorized("Invalid user")
                    username =  result.get('sub')
                    request.environ['REMOTE_USER'] = str(username)
                    self._build_payload(domain, request)
                except Exception as e:
                    LOG.debug(e)
                    LOG.warning('Invalid Auth token received')
                    raise exception.Unauthorized("Invalid user")
        elif (request.environ['REQUEST_METHOD'] == 'POST' and
              request.environ['PATH_INFO'] == '/auth/tokens' and
              len(request.body) > 0):
            body = json.loads(request.body)
            try:
                user_id = body['auth']['identity']['password']['user'].get('id')
            except:
                user_id = None
            domain = self._domain_lookup(request)
            if (domain is None or domain == 'default'):
                return
            else:
                BM_HEADER['Content-Type'] = 'application/x-www-form-urlencoded'
                try:
                    if (user_id is not None):
                        _user = self.identity_api.get_user(user_id)
                        user = _user['name']
                    else:
                        user = body['auth']['identity']['password'][
                            'user']['name']
                    password = body['auth']['identity']['password'][
                        'user']['password']
                    en_user = urllib.quote_plus(user)
                    en_password = urllib.quote_plus(password)
                    payload = "grant_type=password&scope=openid&username={}&password={}".format(
                        en_user, en_password)
                    response = requests.post(IDAAS,
                                             data=payload,
                                             auth=(CLIENTID, SECRET),
                                             headers=BM_HEADER,
                                             verify=False)
                    if response.status_code != 200:
                        LOG.warning('%s credential invalid at bluemix end', user)
                        LOG.warning('Bypassing the request to keystone')
                        return
                    else:
                        new_body = self._change_method_name(body)
                        new_body['auth']['identity']['methods'] = []
                        new_body['auth']['identity']['methods'].append("external")
                        request.body = json.dumps(new_body, indent=True)
                except KeyError as e:
                    LOG.warning('Invalid payload')
                    raise exception.ValidationError(
                        "Invalid payload")
                request.environ['REMOTE_USER'] = user
                request.environ['REMOTE_DOMAIN'] = domain
        else:
            pass
