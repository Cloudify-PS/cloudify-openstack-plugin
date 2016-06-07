#########
# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

import os
import errno
import platform
from getpass import getuser

from cloudify import ctx
from cloudify import context
from cloudify.decorators import operation
from cloudify.exceptions import NonRecoverableError
from openstack_plugin_common import (
    with_nova_client,
    validate_resource,
    use_external_resource,
    transform_resource_name,
    is_external_resource,
    delete_runtime_properties,
    get_resource_id,
    delete_resource_and_runtime_properties,
    OPENSTACK_ID_PROPERTY,
    OPENSTACK_TYPE_PROPERTY,
    OPENSTACK_NAME_PROPERTY,
    COMMON_RUNTIME_PROPERTIES_KEYS
)

RUNTIME_PROPERTIES_KEYS = COMMON_RUNTIME_PROPERTIES_KEYS
KEYPAIR_OPENSTACK_TYPE = 'keypair'

PRIVATE_KEY_PATH_PROP = 'private_key_path'

CLOUDIFY_AGENT = 'cloudify_agent'
PRIVATE_KEY = 'private_key'
PUBLIC_KEY = 'public_key'
SSH_KEY = 'ssh_key'
USER = 'user'
PATH = 'path'
KEY = 'key'


@operation
@with_nova_client
def create(nova_client, args, **kwargs):

    private_key_path = _get_private_key_path()
    pk_exists = _check_private_key_exists(private_key_path)

    if use_external_resource(ctx, nova_client, KEYPAIR_OPENSTACK_TYPE):
        if not pk_exists:
            delete_runtime_properties(ctx, RUNTIME_PROPERTIES_KEYS)
            raise NonRecoverableError(
                'Failed to use external keypair (node {0}): the public key {1}'
                ' is available on Openstack, but the private key could not be '
                'found at {2}'.format(ctx.node.id,
                                      ctx.node.properties['resource_id'],
                                      private_key_path))
        return

    if pk_exists:
        raise NonRecoverableError(
            "Can't create keypair - private key path already exists: {0}"
            .format(private_key_path))

    keypair = {
        'name': get_resource_id(ctx, KEYPAIR_OPENSTACK_TYPE),
    }
    keypair.update(ctx.node.properties[KEYPAIR_OPENSTACK_TYPE], **args)
    transform_resource_name(ctx, keypair)

    keypair = nova_client.keypairs.create(keypair['name'],
                                          keypair.get(PUBLIC_KEY))
    ctx.instance.runtime_properties[OPENSTACK_ID_PROPERTY] = keypair.id
    ctx.instance.runtime_properties[OPENSTACK_TYPE_PROPERTY] = \
        KEYPAIR_OPENSTACK_TYPE
    ctx.instance.runtime_properties[OPENSTACK_NAME_PROPERTY] = keypair.name

    # save real name of keyfile
    ctx.instance.runtime_properties[PRIVATE_KEY] = {
        PATH: private_key_path,
        KEY: keypair.private_key
    }

    try:
        # write private key file
        _mkdir_p(os.path.dirname(private_key_path))
        with open(private_key_path, 'w') as f:
            f.write(keypair.private_key)
        os.chmod(private_key_path, 0600)
    except Exception:
        _delete_private_key_file()
        delete_resource_and_runtime_properties(ctx, nova_client,
                                               RUNTIME_PROPERTIES_KEYS)
        raise


@operation
@with_nova_client
def delete(nova_client, **kwargs):
    if not is_external_resource(ctx):
        ctx.logger.info('deleting keypair')

        _delete_private_key_file()

        nova_client.keypairs.delete(
            ctx.instance.runtime_properties[OPENSTACK_ID_PROPERTY])
    else:
        ctx.logger.info('not deleting keypair since an external keypair is '
                        'being used')

    delete_runtime_properties(ctx, RUNTIME_PROPERTIES_KEYS)


@operation
@with_nova_client
def creation_validation(nova_client, **kwargs):

    def validate_private_key_permissions(private_key_path):
        ctx.logger.debug('checking whether private key file {0} has the '
                         'correct permissions'.format(private_key_path))
        if not os.access(private_key_path, os.R_OK):
            err = 'private key file {0} is not readable'\
                .format(private_key_path)
            ctx.logger.error('VALIDATION ERROR: ' + err)
            raise NonRecoverableError(err)
        ctx.logger.debug('OK: private key file {0} has the correct '
                         'permissions'.format(private_key_path))

    def validate_path_owner(path):
        ctx.logger.debug('checking whether directory {0} is owned by the '
                         'current user'.format(path))
        from pwd import getpwnam, getpwuid

        user = getuser()
        owner = getpwuid(os.stat(path).st_uid).pw_name
        current_user_id = str(getpwnam(user).pw_uid)
        owner_id = str(os.stat(path).st_uid)

        if not current_user_id == owner_id:
            err = '{0} is not owned by the current user (it is owned by {1})'\
                  .format(path, owner)
            ctx.logger.warning('VALIDATION WARNING: {0}'.format(err))
            return
        ctx.logger.debug('OK: {0} is owned by the current user'.format(path))

    validate_resource(ctx, nova_client, KEYPAIR_OPENSTACK_TYPE)

    private_key_path = _get_private_key_path()
    pk_exists = _check_private_key_exists(private_key_path)

    if is_external_resource(ctx):
        if pk_exists:
            if platform.system() == 'Linux':
                validate_private_key_permissions(private_key_path)
                validate_path_owner(private_key_path)
        else:
            err = "can't use external keypair: the public key {0} is " \
                  "available on Openstack, but the private key could not be " \
                  "found at {1}".format(ctx.node.properties['resource_id'],
                                        private_key_path)
            ctx.logger.error('VALIDATION ERROR: {0}'.format(err))
            raise NonRecoverableError(err)
    else:
        if pk_exists:
            err = 'private key path already exists: {0}'.format(
                private_key_path)
            ctx.logger.error('VALIDATION ERROR: {0}'.format(err))
            raise NonRecoverableError(err)
        else:
            err = 'private key directory {0} is not writable'
            while private_key_path:
                if os.path.isdir(private_key_path):
                    if not os.access(private_key_path, os.W_OK | os.X_OK):
                        raise NonRecoverableError(err.format(private_key_path))
                    else:
                        break
                private_key_path, _ = os.path.split(private_key_path)

    ctx.logger.debug('OK: keypair configuration is valid')


def _get_private_key_path():
    openstack_override = {}
    if ctx.type == context.NODE_INSTANCE:
        openstack_override = ctx.instance.runtime_properties.get('openstack_override')
    elif ctx.type == context.RELATIONSHIP_INSTANCE:
        openstack_override = ctx.source.instance.runtime_properties.get('openstack_override')
        if not openstack_override:
            openstack_override = ctx.target.instance.runtime_properties.get('openstack_override')
    # case when we have some override settings
    if openstack_override and 'tenant_name' in openstack_override:
        return os.path.expanduser(
            "~/tenant-keys/" + openstack_override['tenant_name'] + "/" + ctx.node.properties[PRIVATE_KEY_PATH_PROP]
        )
    return os.path.expanduser(ctx.node.properties[PRIVATE_KEY_PATH_PROP])


def _delete_private_key_file():
    private_key_path = _get_private_key_path()
    ctx.logger.debug('deleting private key file at {0}'.format(
        private_key_path))
    try:
        os.remove(private_key_path)
    except OSError as e:
        if e.errno == errno.ENOENT:
            # file was already deleted somehow
            pass
        raise


def _check_private_key_exists(private_key_path):
    return os.path.isfile(private_key_path)


def _mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno == errno.EEXIST and os.path.isdir(path):
            return
        raise

@operation
def server_connect_to_keypair(**kwargs):
    host_rt_properties = ctx.source.instance.runtime_properties
    target_rt_properties = ctx.target.instance.runtime_properties
    if SSH_KEY not in host_rt_properties:
        host_rt_properties[SSH_KEY] = {}
    if PRIVATE_KEY in target_rt_properties:
        host_rt_properties[SSH_KEY][PATH] = target_rt_properties[PRIVATE_KEY].get(PATH)
        host_rt_properties[SSH_KEY][KEY] = target_rt_properties[PRIVATE_KEY].get(KEY)
    if PUBLIC_KEY in target_rt_properties:
        host_rt_properties[SSH_KEY][USER] = target_rt_properties[PUBLIC_KEY].get(USER)
    if CLOUDIFY_AGENT not in host_rt_properties:
        host_rt_properties[CLOUDIFY_AGENT] = {}
    if target_rt_properties[PRIVATE_KEY].get(PATH):
        host_rt_properties[CLOUDIFY_AGENT][KEY] = target_rt_properties[PRIVATE_KEY].get(PATH)
    ctx.source.instance.update()


@operation
def server_disconnect_from_keypair(**kwargs):
    host_rt_properties = ctx.source.instance.runtime_properties
    if SSH_KEY in host_rt_properties:
        del host_rt_properties[SSH_KEY]
    if CLOUDIFY_AGENT in host_rt_properties:
        del host_rt_properties[CLOUDIFY_AGENT]
