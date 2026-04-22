import os
import argparse

resolver_container_cmd_dict={
    'bind':'docker run -d --name ruc-bind --network ruc-test-net --ip 172.22.1.1 ruc-bind:9.20.3',
    'powerdns':'docker run -d --name ruc-powerdns --network ruc-test-net --ip 172.22.1.2 ruc-powerdns:5.1.3',
    'unbound':'docker run -d --name ruc-unbound --network ruc-test-net --ip 172.22.1.3 ruc-unbound:1.22.0',
    'knot':'docker run -d --name ruc-knot --network ruc-test-net --ip 172.22.1.4 ruc-knot:5.7.4',
    'technitium':'docker run -d --name ruc-technitium --network ruc-test-net --ip 172.22.1.5 ruc-technitium:13.1'
}

# #python3 renew_resolver.py --resolver bind
def remove_resolver_container(resolver):
    os.system(f'docker stop ruc-{resolver} && docker rm ruc-{resolver}')

def create_resolver_container(resolver):
    os.system(resolver_container_cmd_dict[resolver])

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--resolver')
    args=parser.parse_args()

    resolver=args.resolver
    remove_resolver_container(resolver)
    create_resolver_container(resolver)