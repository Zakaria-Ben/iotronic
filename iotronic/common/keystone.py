# coding=utf-8
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

from keystoneclient import exceptions as ksexception
from oslo_config import cfg
from six.moves.urllib import parse

from iotronic.common import exception
from iotronic.common.i18n import _

CONF = cfg.CONF

keystone_opts = [
    cfg.StrOpt('region_name',
               help='The region used for getting endpoints of OpenStack'
                    'services.'),
]

CONF.register_opts(keystone_opts, group='keystone')
CONF.import_group('keystone_authtoken', 'keystonemiddleware.auth_token')


def _is_apiv3(auth_url, auth_version):
    """Checks if V3 version of API is being used or not.

    This method inspects auth_url and auth_version, and checks whether V3
    version of the API is being used or not.

    :param auth_url: a http or https url to be inspected (like
        'http://127.0.0.1:9898/').
    :param auth_version: a string containing the version (like 'v2', 'v3.0')
    :returns: True if V3 of the API is being used.
    """
    return auth_version == 'v3.0' or '/v3' in parse.urlparse(auth_url).path


def _get_ksclient(token=None):
    auth_url = CONF.keystone_authtoken.auth_uri
    if not auth_url:
        raise exception.KeystoneFailure(_('Keystone API endpoint is missing'))

    auth_version = CONF.keystone_authtoken.auth_version
    api_v3 = _is_apiv3(auth_url, auth_version)

    if api_v3:
        from keystoneclient.v3 import client
    else:
        from keystoneclient.v2_0 import client

    auth_url = get_keystone_url(auth_url, auth_version)
    try:
        if token:
            return client.Client(token=token, auth_url=auth_url)
        else:
            return client.Client(
                username=CONF.keystone_authtoken.admin_user,
                password=CONF.keystone_authtoken.admin_password,
                tenant_name=CONF.keystone_authtoken.admin_tenant_name,
                region_name=CONF.keystone.region_name,
                auth_url=auth_url)
    except ksexception.Unauthorized:
        raise exception.KeystoneUnauthorized()
    except ksexception.AuthorizationFailure as err:
        raise exception.KeystoneFailure(_('Could not authorize in Keystone:'
                                          ' %s') % err)


def get_keystone_url(auth_url, auth_version):
    """Gives an http/https url to contact keystone.

    Given an auth_url and auth_version, this method generates the url in
    which keystone can be reached.

    :param auth_url: a http or https url to be inspected (like
        'http://127.0.0.1:9898/').
    :param auth_version: a string containing the version (like v2, v3.0, etc)
    :returns: a string containing the keystone url
    """
    api_v3 = _is_apiv3(auth_url, auth_version)
    api_version = 'v3' if api_v3 else 'v2.0'
    # NOTE(lucasagomes): Get rid of the trailing '/' otherwise urljoin()
    #   fails to override the version in the URL
    return parse.urljoin(auth_url.rstrip('/'), api_version)


def get_service_url(service_type='iot', endpoint_type='internal'):
    """Wrapper for get service url from keystone service catalog.

    Given a service_type and an endpoint_type, this method queries keystone
    service catalog and provides the url for the desired endpoint.

    :param service_type: the keystone service for which url is required.
    :param endpoint_type: the type of endpoint for the service.
    :returns: an http/https url for the desired endpoint.
    """
    ksclient = _get_ksclient()

    if not ksclient.has_service_catalog():
        raise exception.KeystoneFailure(_('No Keystone service catalog '
                                          'loaded'))

    try:
        endpoint = ksclient.service_catalog.url_for(
            service_type=service_type,
            endpoint_type=endpoint_type,
            region_name=CONF.keystone.region_name)

    except ksexception.EndpointNotFound:
        raise exception.CatalogNotFound(service_type=service_type,
                                        endpoint_type=endpoint_type)

    return endpoint


def get_admin_auth_token():
    """Get an admin auth_token from the Keystone."""
    ksclient = _get_ksclient()
    return ksclient.auth_token


def token_expires_soon(token, duration=None):
    """Determines if token expiration is about to occur.

    :param duration: time interval in seconds
    :returns: boolean : true if expiration is within the given duration
    """
    ksclient = _get_ksclient(token=token)
    return ksclient.auth_ref.will_expire_soon(stale_duration=duration)



######################################################################


from keystoneauth1 import exceptions as kaexception
from keystoneauth1 import loading as kaloading
from keystoneauth1 import service_token
from keystoneauth1 import token_endpoint
from oslo_log import log as logging
import six

from iotronic.common import exception

LOG = logging.getLogger(__name__)

def ks_exceptions(f):
    """Wraps keystoneclient functions and centralizes exception handling."""
    @six.wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except kaexception.EndpointNotFound:
            service_type = kwargs.get('service_type', 'iot')
            endpoint_type = kwargs.get('endpoint_type', 'internal')
            raise exception.CatalogNotFound(
                service_type=service_type, endpoint_type=endpoint_type)
        except (kaexception.Unauthorized, kaexception.AuthorizationFailure):
            raise exception.KeystoneUnauthorized()
        except (kaexception.NoMatchingPlugin,
                kaexception.MissingRequiredOptions) as e:
            raise exception.ConfigInvalid(six.text_type(e))
        except Exception as e:
            LOG.exception('Keystone request failed: %(msg)s',
                          {'msg': six.text_type(e)})
            raise exception.KeystoneFailure(six.text_type(e))
    return wrapper


@ks_exceptions
def get_session(group, **session_kwargs):
    """Loads session object from options in a configuration file section.
    The session_kwargs will be passed directly to keystoneauth1 Session
    and will override the values loaded from config.
    Consult keystoneauth1 docs for available options.
    :param group: name of the config section to load session options from
    """
    return kaloading.load_session_from_conf_options(
        CONF, group, **session_kwargs)


@ks_exceptions
def get_auth(group, **auth_kwargs):
    """Loads auth plugin from options in a configuration file section.
    The auth_kwargs will be passed directly to keystoneauth1 auth plugin
    and will override the values loaded from config.
    Note that the accepted kwargs will depend on auth plugin type as defined
    by [group]auth_type option.
    Consult keystoneauth1 docs for available auth plugins and their options.
    :param group: name of the config section to load auth plugin options from
    """
    try:
        auth = kaloading.load_auth_from_conf_options(CONF, group,
                                                     **auth_kwargs)
    except kaexception.MissingRequiredOptions:
        LOG.error('Failed to load auth plugin from group %s', group)
        raise
    return auth


@ks_exceptions
def get_adapter(group, **adapter_kwargs):
    """Loads adapter from options in a configuration file section.
    The adapter_kwargs will be passed directly to keystoneauth1 Adapter
    and will override the values loaded from config.
    Consult keystoneauth1 docs for available adapter options.
    :param group: name of the config section to load adapter options from
    """
    return kaloading.load_adapter_from_conf_options(CONF, group,
                                                    **adapter_kwargs)


def get_service_auth(context, endpoint, service_auth):
    """Create auth plugin wrapping both user and service auth.
    When properly configured and using auth_token middleware,
    requests with valid service auth will not fail
    if the user token is expired.
    Ideally we would use the plugin provided by auth_token middleware
    however this plugin isn't serialized yet.
    """
    # TODO(pas-ha) use auth plugin from context when it is available
    user_auth = token_endpoint.Token(endpoint, context.auth_token)
    return service_token.ServiceTokenAuthWrapper(user_auth=user_auth,
service_auth=service_auth)
