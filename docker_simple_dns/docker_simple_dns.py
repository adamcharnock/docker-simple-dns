#!/usr/bin/env python3
import logging
from functools import partial
from ipaddress import IPv4Address, IPv6Address, ip_address
from itertools import chain
from pathlib import Path
from random import randint
from typing import NamedTuple, List, Union

import docker
import argparse
import shutil
import signal
import sys

DELIMITER = "### DOCKER HOSTS ###"

logger = logging.getLogger('dev_tools')

IpAddress = Union[IPv4Address, IPv6Address]


class Host(NamedTuple):
    """Data structure for storing a containers IP/host information"""
    container_id: str
    ip: IpAddress
    names: List[str]
    domain: str = ""

    def names_for_hosts_file(self):
        """Determine the names to be rendered into the hosts file"""
        qualified_names = []
        if self.domain:
            qualified_names = [f"{n}.{self.domain}" for n in self.names]
        return self.names + qualified_names


class HostList(list):
    """A list with some useful additional functionality"""

    def get_ip_addresses(self: List[Host]) -> List[IpAddress]:
        """Get all IPs for the hosts in the list"""
        ip_addresses = []
        for host in self:
            if host.ip not in ip_addresses:
                ip_addresses.append(host.ip)
        return ip_addresses

    def hosts_for_ip(self: List[Host], ip: IpAddress):
        """Get all hosts for a given IP"""
        hosts = []
        for host in self:
            if host.ip == ip:
                hosts.append(host)
        return hosts

    def discard_container(self: List[Host], container_id: str) -> "HostList":
        """Remove a container ID from the list and return the modified list"""
        return HostList([h for h in self if h.container_id != container_id])


def make_handler(hosts_path):
    """Make a shutdown handler

    We cleanup the hosts file on shutdown
    """
    def signal_handler(*_):
        logging.info("Removing all hosts before exit...")
        update_hosts_file(hosts_path, hosts=HostList())
        sys.exit(0)
    return signal_handler


def main():
    """ The main program loop

    This initially loads all container data, then listens for container
    start & stop events.
    """

    logger.info(f"Starting...")

    #
    # Lots of setup
    #
    hosts = HostList()

    args = parse_args()
    hosts_path = Path(args.file)
    docker_socket = Path(args.socket)
    default_domain = args.default_domain

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format=f"[%(name)s] %(filename)s:%(lineno)d %(levelname)s %(message)s"
    )

    if not docker_socket.exists():
        logger.critical("No socket found at %s. Perhaps set (or double-check) the --socket argument", docker_socket)
        return

    if not docker_socket.is_socket():
        logger.critical("File at %s is not a socket", docker_socket)
        return

    # We need to call update_hosts_file() in a few places,
    # so let's setup those args now to make calling it cleaner
    update_hosts_file_ = partial(
        update_hosts_file,
        hosts_path=hosts_path,
        ipv4=not args.no_ipv4,
        ipv6=not args.no_ipv6,
    )

    # We will also need to call get_container_hosts() in a few places too.
    # Wrap it up here to keep the calls clean
    def get_container_hosts_(container_id_):
        return get_container_hosts(
            container_data=get_container_data(docker_client, container_id_),
            default_domain=default_domain,
        )

    # Register the exit signals
    if not args.no_cleanup:
        signal.signal(signal.SIGINT, make_handler(hosts_path))
        signal.signal(signal.SIGTERM, make_handler(hosts_path))

    docker_client = docker.APIClient(base_url="unix://%s" % docker_socket)
    events = docker_client.events(decode=True)

    #
    # The program control flow begins below
    #

    logger.info(f"Fetching container data from Docker socket at {args.socket}")
    container_ids = docker_client.containers(quiet=True, all=False)
    logger.debug("Received container IDs: %s", container_ids)

    for c in container_ids:
        hosts += get_container_hosts_(container_id_=c["Id"])

    logger.info(f"Writing containers to hosts file")
    update_hosts_file_(hosts=hosts)
    logger.info(f"Writing complete. Will now wait for docker events...")

    # Listen for events to keep the hosts file updated
    for e in events:
        if e["Type"] != "container":
            continue

        status = e["status"]
        if status == "start":
            container_id = e["id"]
            logger.info(f"Received {status} event for {container_id}. Updating hosts file")
            hosts += get_container_hosts_(container_id)
            update_hosts_file_(hosts=hosts)

        if status == "stop" or status == "die" or status == "destroy":
            container_id = e["id"]
            logger.info(f"Received {status} event for {container_id}. Updating hosts file")
            hosts = hosts.discard_container(container_id)
            update_hosts_file_(hosts=hosts)


def get_container_data(docker_client: docker.APIClient, container_id: str) -> dict:
    """Get the container data from docker"""
    data = docker_client.inspect_container(container_id)
    logger.debug("Received container: %s", data)
    return data


def get_container_hosts(container_data: dict, default_domain: str) -> HostList[Host]:
    """Create the host data structure from data provided by docker"""
    container_hostname = container_data["Config"]["Hostname"]
    container_name = container_data["Name"].strip("/")
    container_ipv4 = container_data["NetworkSettings"]["IPAddress"]
    container_ipv6 = container_data["NetworkSettings"]["GlobalIPv6Address"]
    domain = container_data["Config"]["Domainname"] or default_domain or ""
    container_id = container_data["Id"]

    found_hosts = HostList()

    if container_ipv4:
        found_hosts.append(
            Host(
                container_id=container_id,
                ip=ip_address(container_ipv4),
                names=[container_name, container_hostname],
                domain=domain,
            )
        )

    if container_ipv6:
        found_hosts.append(
            Host(
                container_id=container_id,
                ip=ip_address(container_ipv6),
                names=[container_name, container_hostname],
                domain=domain,
            )
        )

    for values in container_data["NetworkSettings"]["Networks"].values():
        aliases = values["Aliases"]

        if aliases:
            if values["IPAddress"]:
                found_hosts.append(
                    Host(
                        container_id=container_id,
                        ip=ip_address(values["IPAddress"]),
                        names=aliases + [container_name, container_hostname],
                        domain=domain,
                    )
                )

            if values["GlobalIPv6Address"]:
                found_hosts.append(
                    Host(
                        container_id=container_id,
                        ip=ip_address(values["GlobalIPv6Address"]),
                        names=aliases + [container_name, container_hostname],
                        domain=domain,
                    )
                )

    logger.debug("Parsed host data: %s", found_hosts)
    return found_hosts


def update_hosts_file(hosts_path: Path, hosts: HostList[Host], ipv4=True, ipv6=True):
    """Write hosts data to the hosts file"""
    logging.debug("Updating hosts file")

    new_hosts: List[str] = []

    for ip_address in hosts.get_ip_addresses():
        # Skip this v4/6 address if we have been told to ignore it
        if ip_address.version == 4 and not ipv4:
            logger.debug("Skipping IP %s because we are excluding IPv4 addresses", ip_address)
            continue
        if ip_address.version == 6 and not ipv6:
            logger.debug("Skipping IP %s because we are excluding IPv6 addresses", ip_address)
            continue

        # Get the host records for this IP
        hosts_ = hosts.hosts_for_ip(ip_address)
        # Get the host names (this will add the domain if available)
        names = list(chain(*(h.names_for_hosts_file() for h in hosts_)))
        # Ensure the names are unique, but maintain order
        names = sorted(set(names), key=names.index)
        new_hosts.append(
            f"{str(ip_address).ljust(42)}{' '.join(names)}"
        )

    if not hosts_path.exists():
        file_content = ''
    else:
        with hosts_path.open('r'):
            file_content = hosts_path.read_text('utf8')

    parts = file_content.split(DELIMITER)
    if len(parts) > 1:
        # Has existing docker host data. Just get everything before and after
        # that host data
        pre_content, _, *other_content = parts
    else:
        pre_content, *other_content = parts

    new_content = '\n'.join(new_hosts)
    other_content = ''.join(other_content)
    file_content = (
        pre_content,
        DELIMITER,
        new_content,
        DELIMITER,
        other_content,
    )
    file_content = '\n'.join(content.strip() for content in file_content if content)

    tmp_hosts_path = hosts_path.parent / f'.tmp.{randint(0, 100000)}.{hosts_path.name}'
    try:
        logger.debug("Writing %s characters to temporary hosts file at %s", len(file_content), tmp_hosts_path)
        with tmp_hosts_path.open('w') as f:
            f.write(file_content)
        logger.debug("Moving temporary file to %s", hosts_path)
        shutil.move(f.name, str(hosts_path))
    finally:
        logger.debug("Cleaning up temporary file")
        tmp_hosts_path.unlink(missing_ok=True)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Synchronize running docker container IPs with hosts file (e.g. /etc/hosts)."
    )
    parser.add_argument(
        "--socket",
        type=str,
        default="tmp/docker.sock",
        help="The docker socket to listen for docker events",
    )
    parser.add_argument(
        "--file",
        type=str,
        default="/tmp/hosts",
        help="The destination hosts file which the container host & IP information will be written to",
    )
    parser.add_argument(
        "--default-domain",
        type=str,
        default="",
        help="The default domain to append to hosts names. Used if not specified on the docker container"
    )
    parser.add_argument(
        "--no-ipv4",
        action="store_true",
        help="Do not enter IPv4 addresses in the hosts file"
    )
    parser.add_argument(
        "--no-ipv6",
        action="store_true",
        help="Do not enter IPv6 addresses in the hosts file"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable more verbose logging"
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Skip cleaning up the hosts file on exit"
    )

    return parser.parse_args()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
