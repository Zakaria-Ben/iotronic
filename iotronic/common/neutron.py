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


from neutronclient.common import exceptions as neutron_exceptions
from neutronclient.v2_0 import client as clientv20
from oslo_log import log
from oslo_config import cfg
from iotronic.common import exception
from iotronic.common.i18n import _
from iotronic.common import keystone

from keystoneauth1 import identity
from keystoneauth1 import session

CONF = cfg.CONF

LOG = log.getLogger(__name__)

neutron_opts = [
    cfg.StrOpt('url',
               default='http://localhost:9696/',
               help=('URL neutron')),
    cfg.StrOpt('retries',
               default=3,
               help=('retries neutron')),
    cfg.StrOpt('auth_strategy',
               default='noauth',
               help=('auth_strategy neutron')),
    cfg.StrOpt('username',
               default='neutron',
               help=('neutron username')),
    cfg.StrOpt('password',
               default='0penstack',
               help=('password')),
    cfg.StrOpt('project_name',
               default='service',
               help=('service')),
    cfg.StrOpt('project_domain_name',
               default='default',
               help=('domain id')),
    cfg.StrOpt('auth_url',
               default='http://localhost:35357',
               help=('auth')),
    cfg.StrOpt('project_domain_id',
               default='default',
               help=('project domain id')),
cfg.StrOpt('user_domain_id',
               default='default',
               help=('user domain id')),
]

CONF.register_opts(neutron_opts, 'neutron')

DEFAULT_NEUTRON_URL = CONF.neutron.url

_NEUTRON_SESSION = None




"""def _get_neutron_session():
    global _NEUTRON_SESSION
    if not _NEUTRON_SESSION:
        _NEUTRON_SESSION = keystone.get_session('neutron')
    return _NEUTRON_SESSION
"""

def get_client(token=None):
    auth = identity.Password(auth_url=CONF.neutron.auth_url, username = CONF.neutron.username,
                             password = CONF.neutron.password, project_name = CONF.neutron.project_name,
                             project_domain_id = CONF.neutron.project_domain_id,
                             user_domain_id = CONF.neutron.user_domain_id)
    sess = session.Session(auth=auth)
    neutron = clientv20.Client(session=sess)
    return neutron


"""    params = {'retries': CONF.neutron.retries}
    url = CONF.neutron.url
    if CONF.neutron.auth_strategy == 'noauth':
        params['endpoint_url'] = url or DEFAULT_NEUTRON_URL
        params['auth_strategy'] = 'noauth'
        ##params.update({
        ##    'timeout': CONF.neutron.url_timeout or CONF.neutron.timeout,
        ##    'insecure': CONF.neutron.insecure,
        ##    'ca_cert': CONF.neutron.cafile})
    else:
        session = _get_neutron_session()
        if token is None:
            params['session'] = session
            # NOTE(pas-ha) endpoint_override==None will auto-discover
            # endpoint from Keystone catalog.
            # Region is needed only in this case.
            # SSL related options are ignored as they are already embedded
            # in keystoneauth Session object
            if url:
                params['endpoint_override'] = url
            else:
                params['region_name'] = CONF.keystone.region_name
        else:
            params['token'] = token
            params['endpoint_url'] = url or keystone.get_service_url(
                session, service_type='network')
            params.update({
                'timeout': CONF.neutron.url_timeout or CONF.neutron.timeout,
                'insecure': CONF.neutron.insecure,
                'ca_cert': CONF.neutron.cafile})

    return clientv20.Client(**params)

"""

def subnet_info(subnet_uuid):
    client = get_client()
    try:
        info = client.show_subnet(subnet_uuid)
        return info
    except Exception as e:
        LOG.error(str(e))


def unbind_neutron_port(port_id, client=None):
    """Unbind a neutron port

    Remove a neutron port's binding profile and host ID so that it returns to
    an unbound state.

    :param port_id: Neutron port ID.
    :param client: Optional a Neutron client object.
    :raises: NetworkError
    """

    if not client:
        client = get_client()

    body = {'port': {'binding:host_id': '',
                     'binding:profile': {}}}

    try:
        client.update_port(port_id, body)
    # NOTE(vsaienko): Ignore if port was deleted before calling vif detach.
    except neutron_exceptions.PortNotFoundClient:
        LOG.info('Port %s was not found while unbinding.', port_id)
    except neutron_exceptions.NeutronClientException as e:
        msg = (_('Unable to clear binding profile for '
                 'neutron port %(port_id)s. Error: '
                 '%(err)s') % {'port_id': port_id, 'err': e})
        LOG.exception(msg)
        raise exception.NetworkError(msg)


def update_port_address(port_id, address):
    """Update a port's mac address.

    :param port_id: Neutron port id.
    :param address: new MAC address.
    :raises: FailedToUpdateMacOnPort
    """
    client = get_client()
    port_req_body = {'port': {'mac_address': address}}

    try:
        msg = (_("Failed to get the current binding on Neutron "
                 "port %s.") % port_id)
        port = client.show_port(port_id).get('port', {})
        binding_host_id = port.get('binding:host_id')
        binding_profile = port.get('binding:profile')

        if binding_host_id:
            # Unbind port before we update it's mac address, because you can't
            # change a bound port's mac address.
            msg = (_("Failed to remove the current binding from "
                     "Neutron port %s, while updating its MAC "
                     "address.") % port_id)
            unbind_neutron_port(port_id, client=client)
            port_req_body['port']['binding:host_id'] = binding_host_id
            port_req_body['port']['binding:profile'] = binding_profile

        msg = (_("Failed to update MAC address on Neutron port %s.") % port_id)
        client.update_port(port_id, port_req_body)
    except (neutron_exceptions.NeutronClientException, exception.NetworkError):
        LOG.exception(msg)
        raise exception.FailedToUpdateMacOnPort(port_id=port_id)


def _verify_security_groups(security_groups, client):
    """Verify that the security groups exist.

    :param security_groups: a list of security group UUIDs; may be None or
        empty
    :param client: Neutron client
    :raises: NetworkError
    """

    if not security_groups:
        return
    try:
        neutron_sec_groups = (
            client.list_security_groups().get('security_groups', []))
    except neutron_exceptions.NeutronClientException as e:
        msg = (_("Could not retrieve security groups from neutron: %(exc)s") %
               {'exc': e})
        LOG.exception(msg)
        raise exception.NetworkError(msg)

    existing_sec_groups = [sec_group['id'] for sec_group in neutron_sec_groups]
    missing_sec_groups = set(security_groups) - set(existing_sec_groups)
    if missing_sec_groups:
        msg = (_('Could not find these security groups (specified via iotronic '
                 'config) in neutron: %(ir-sg)s')
               % {'ir-sg': list(missing_sec_groups)})
        LOG.error(msg)
        raise exception.NetworkError(msg)

def add_port_to_network(wagent, network_uuid, subnet_uuid, security_groups=None):

    client = get_client()
    _verify_security_groups(security_groups, client)

    #subnet_uuid = str("006ec006-b7ba-4e17-9aab-a87ebcc6ed6f")
    LOG.debug('For wagent %(wagent)s, creating neutron port on network '
              '%(network_uuid)s.',
              {'wagent': wagent, 'network_uuid': network_uuid})

    body = {
        'port': {
            'network_id': network_uuid,
            'admin_state_up': True,
            'device_owner': 'IOT:board',
            'binding:host_id': wagent,
            'fixed_ips': [{
                'subnet_id': subnet_uuid
            }]
        }
    }

    if security_groups:
        body['port']['security_groups'] = security_groups

    try:
        port = client.create_port(body)
    except neutron_exceptions.NeutronClientException as e:
        LOG.warning("Could not create neutron port for wagent's "
                    "%(wagent)s on the neutron "
                    "network %(net)s. %(exc)s",
                    {'net': network_uuid, 'wagent': wagent,
                     'exc': e})
    else:
        return port

def delete_port(wagent, port_uuid):

    client = get_client()
    LOG.debug('For wagent %(wagent)s, removing neutron port %(port_uuid)s',
                  {'wagent': wagent,'port_uuid':port_uuid})
    try:
        port = client.delete_port(port_uuid)
        return 1

    except neutron_exceptions.NeutronClientException as e:
        LOG.warning("Could not delete neutron port from wagent's "
                    "%(wagent)s : %(exc)s ",{'wagent': wagent, 'exc':e})
        return 0



