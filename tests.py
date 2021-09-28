from ipaddress import ip_address
from pathlib import Path
from tempfile import TemporaryDirectory

from docker_simple_dns.runner import Host, HostList, get_container_hosts, update_hosts_file


def test_host_names_for_hosts_file_without_domain():
    host = Host(ip=ip_address('1.2.3.4'), names=['foo', 'bar'], container_id='')
    assert host.names_for_hosts_file() == ['foo', 'bar']


def test_host_names_for_hosts_file_with_domain():
    host = Host(ip=ip_address('1.2.3.4'), names=['foo', 'bar'], container_id='', domain='example.com')
    assert host.names_for_hosts_file() == ['foo', 'bar', 'foo.example.com', 'bar.example.com']


def test_host_list_get_ip_addresses():
    host1 = Host(ip=ip_address('1.1.1.1'), names=['foo', 'bar'], container_id='')
    host2 = Host(ip=ip_address('2.2.2.2'), names=['foo', 'cow'], container_id='')
    host3 = Host(ip=ip_address('2.2.2.2'), names=['baz'], container_id='')
    host_list = HostList([host1, host2, host3])
    assert host_list.get_ip_addresses() == [ip_address('1.1.1.1'), ip_address('2.2.2.2')]


def test_host_list_hosts_for_ip():
    host1 = Host(ip=ip_address('1.1.1.1'), names=['foo', 'bar'], container_id='')
    host2 = Host(ip=ip_address('2.2.2.2'), names=['foo', 'cow'], container_id='')
    host3 = Host(ip=ip_address('2.2.2.2'), names=['baz'], container_id='')
    host_list = HostList([host1, host2, host3])
    assert host_list.hosts_for_ip(ip_address('2.2.2.2')) == [host2, host3]


def test_host_list_discard_container():
    host1 = Host(ip=ip_address('1.1.1.1'), names=[], container_id='1')
    host2 = Host(ip=ip_address('1.1.1.1'), names=[], container_id='2')
    host_list = HostList([host1, host2])
    assert list(host_list.discard_container('2')) == [host1]


def test_get_container_hosts():
    hosts = get_container_hosts(container_data=CONTAINER_DATA, default_domain='default.com')
    assert len(hosts) == 4

    ipv4, ipv6, alias4, alias6 = hosts
    assert ipv4.container_id == 'abc'
    assert ipv4.ip == ip_address('1.1.1.1')
    assert ipv4.names == ['myname', 'myhostname']
    assert ipv4.domain == 'example.com'

    assert ipv6.container_id == 'abc'
    assert ipv6.ip == ip_address('2001:0db8:85a3:0000:0000:8a2e:0370:7334')
    assert ipv6.names == ['myname', 'myhostname']
    assert ipv6.domain == 'example.com'

    assert alias4.container_id == 'abc'
    assert alias4.ip == ip_address('1.1.1.1')
    assert alias4.names == ['alias1', 'alias2', 'myname', 'myhostname']
    assert alias4.domain == 'example.com'

    assert alias6.container_id == 'abc'
    assert alias6.ip == ip_address('2001:0db8:85a3:0000:0000:8a2e:0370:7334')
    assert alias6.names == ['alias1', 'alias2', 'myname', 'myhostname']
    assert alias6.domain == 'example.com'


def test_update_hosts_file_blank():
    hosts = get_container_hosts(container_data=CONTAINER_DATA, default_domain='default.com')

    with TemporaryDirectory() as d:
        hosts_path = Path(d) / 'hosts'
        update_hosts_file(
            hosts_path=hosts_path,
            hosts=hosts,
        )
        content = hosts_path.read_text()

    # fmt: off
    lines = content.split('\n')
    assert lines[0] == '### DOCKER HOSTS ###'
    assert lines[1] == '1.1.1.1                                   myname myhostname myname.example.com myhostname.example.com alias1 alias2 alias1.example.com alias2.example.com'  # noqa
    assert lines[2] == '2001:db8:85a3::8a2e:370:7334              myname myhostname myname.example.com myhostname.example.com alias1 alias2 alias1.example.com alias2.example.com'  # noqa
    assert lines[3] == '### DOCKER HOSTS ###'
    # fmt: on


def test_update_hosts_file_pre_content():
    hosts = get_container_hosts(container_data=CONTAINER_DATA, default_domain='default.com')

    with TemporaryDirectory() as d:
        hosts_path = Path(d) / 'hosts'
        with hosts_path.open('w') as f:
            f.write('9.9.9.9   existing.host')
        update_hosts_file(
            hosts_path=hosts_path,
            hosts=hosts,
        )
        content = hosts_path.read_text()

    lines = content.split('\n')
    assert lines[0] == '9.9.9.9   existing.host'
    assert lines[1] == '### DOCKER HOSTS ###'
    assert lines[4] == '### DOCKER HOSTS ###'


def test_update_hosts_file_post_content():
    hosts = get_container_hosts(container_data=CONTAINER_DATA, default_domain='default.com')

    with TemporaryDirectory() as d:
        hosts_path = Path(d) / 'hosts'
        with hosts_path.open('w') as f:
            f.write('### DOCKER HOSTS ###\n')
            f.write('### DOCKER HOSTS ###\n')
            f.write('9.9.9.9   existing.host')
        update_hosts_file(
            hosts_path=hosts_path,
            hosts=hosts,
        )
        content = hosts_path.read_text()

    lines = content.split('\n')
    assert lines[0] == '### DOCKER HOSTS ###'
    assert lines[3] == '### DOCKER HOSTS ###'
    assert lines[4] == '9.9.9.9   existing.host'


def test_update_hosts_file_no_ipv4():
    hosts = get_container_hosts(container_data=CONTAINER_DATA, default_domain='default.com')

    with TemporaryDirectory() as d:
        hosts_path = Path(d) / 'hosts'
        update_hosts_file(
            hosts_path=hosts_path,
            hosts=hosts,
            ipv4=False
        )
        content = hosts_path.read_text()

    lines = content.split('\n')
    assert len(lines) == 3
    assert lines[1].startswith('2001:db8:85a3::8a2e:370:7334')


def test_update_hosts_file_no_ipv6():
    hosts = get_container_hosts(container_data=CONTAINER_DATA, default_domain='default.com')

    with TemporaryDirectory() as d:
        hosts_path = Path(d) / 'hosts'
        update_hosts_file(
            hosts_path=hosts_path,
            hosts=hosts,
            ipv6=False
        )
        content = hosts_path.read_text()

    lines = content.split('\n')
    assert len(lines) == 3
    assert lines[1].startswith('1.1.1.1')


# fmt: off
CONTAINER_DATA = {
    'Id': 'abc',
    'Name': 'myname',
    'Config': {
        'Hostname': 'myhostname',
        'Domainname': 'example.com',
    },
    'NetworkSettings': {
        'IPAddress': '1.1.1.1',
        'GlobalIPv6Address': '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        'Networks': {
            'mynetwork': {
                'Aliases': ['alias1', 'alias2'],
                'IPAddress': '1.1.1.1',
                'GlobalIPv6Address': '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
            }
        }
    }
}
# fmt: on
