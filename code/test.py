# from openstack import connection
# import json
# import os
#
# from keystoneauth1 import loading
# from keystoneauth1 import session
# from novaclient import client
# loader = loading.get_plugin_loader('password')
# auth = loader.load_from_options(auth_url="http://10.0.2.11/identity/v3",
#                                 username="admin", password="shantanu",
#                                 project_name="admin",
#                                 project_domain_id="default",
#                                 user_domain_id="default",
#                                 project_id="f4828a747f48497c9e19776f8b49e2cc")
#
# sess = session.Session(auth=auth)
# nova = client.Client(2, session=sess)
# for VM in nova.servers.list():
#     print VM
