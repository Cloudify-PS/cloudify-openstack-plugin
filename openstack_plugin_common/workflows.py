# Copyright (c) 2015 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from cloudify.decorators import workflow
from cloudify.manager import update_node_instance
from cloudify.plugins import lifecycle


def update(ctx, instance, token, keystore_url, region, tenant_name):
    """update token and url in instance"""
    node_instance = instance._node_instance
    rt_properties = node_instance['runtime_properties']
    rt_properties.update({
        'openstack_override': {
            'token': token,
            'keystore_url': keystore_url,
            'region': region,
            'tenant_name': tenant_name
        }
    })
    version = node_instance['version']
    node_instance['version'] = version if version else 0
    if ctx.local:
        version = node_instance['version']
        state = node_instance.get('state')
        node_id = instance.id
        storage = ctx.internal.handler.storage
        storage.update_node_instance(node_id, version, rt_properties, state)
    else:
        update_node_instance(node_instance)
    ctx.logger.info("Will be used {}".format(
        str(rt_properties)
    ))

def _get_all_nodes_instances(ctx, token, keystore_url, region, tenant_name):
    """return all instances from context nodes"""
    node_instances = set()
    for node in ctx.nodes:
        for instance in node.instances:
            if ('openstack_config' in node.properties and
               token and keystore_url):
                update(ctx, instance, token, keystore_url, region, tenant_name)
            node_instances.add(instance)
    return node_instances


@workflow
def install(ctx, **kwargs):
    """Score install workflow"""
    lifecycle.install_node_instances(
        graph=ctx.graph_mode(),
        node_instances=set(
            _get_all_nodes_instances(
                ctx, kwargs.get('session_token'),
                kwargs.get('keystore_url'),
                kwargs.get('region'),
                kwargs.get('tenant_name')
            )
        )
    )


@workflow
def uninstall(ctx, **kwargs):
    """Score uninstall workflow"""

    lifecycle.uninstall_node_instances(
        graph=ctx.graph_mode(),
        node_instances=set(
            _get_all_nodes_instances(
                ctx, kwargs.get('session_token'),
                kwargs.get('keystore_url'),
                kwargs.get('region'),
                kwargs.get('tenant_name')
            )
        )
    )
