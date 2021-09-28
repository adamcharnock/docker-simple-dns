# Docker Simple DNS

A simple "etc/hosts" file injection tool to resolve names of local Docker containers on the host.

You can also use the contained `docker-compose.yaml` file to start a CoreDNS server. This CoreDNS server 
will read its data from the generated hosts file, and serve up A & AAAA records in response to queries.

## Running (local /etc/hosts file only)

You can inject host entries into your local `/etc/hosts` file as follows:

    docker run -d \
        -v /var/run/docker.sock:/tmp/docker.sock \
        -v /etc/hosts:/tmp/hosts \
        adamcharnock/docker-simple-dns

The `docker.sock` is mounted to listen for Docker events and automatically register container's IPs.
The entries will be removed from the hosts file when `docker_simple_dns` exits (this is configurable, see below)


## Running (as DNS server)

You can start a DNS server as follows:

    docker-compose up

This will start `docker_simple_dns` pointing to an isolated hosts file (not your system's `/etc/hosts`),
and also start CoreDNS serving DNS records out of the same hosts file.

In this case it is a good idea to ensure the hosts are valid-looking domains. You can do 
this by specifying the containing domain name for your docker containers. You can do this 
in one of two ways:

1. Specify the `Domainname` when starting containers using the `docker run --domainname=...` argument
2. Specify the `docker_simple_dns --default-domain=...` argument. This is set to `docker.local` in the
   default `docker-compose.yaml` configuration. 

For example:

```
       | DOMAIN TO LOOKUP |     | DNS CONTAINER IP |
$ host nginx.docker.local        172.21.0.2
Using domain server:
Name: 172.21.0.2
Address: 172.21.0.2#53
Aliases:

nginx.docker.local has address 172.17.0.5
nginx.docker.local has IPv6 address 2001:0db8:85a3::5
```


## Options

```
❱ docker_simple_dns -h
usage: docker_simple_dns [-h] [--socket SOCKET] [--file FILE] 
                         [--default-domain DEFAULT_DOMAIN] 
                         [--no-ipv4] [--no-ipv6] [--debug] [--no-cleanup]

Synchronize running docker container IPs with hosts file (e.g. /etc/hosts).

optional arguments:
  -h, --help            show this help message and exit
  --socket SOCKET       The docker socket to listen for docker events
  --file FILE           The destination hosts file which the container host & IP information will be written to
  --default-domain DEFAULT_DOMAIN
                        The default domain to append to host names. Used if not specified on the docker container
  --no-ipv4             Do not enter IPv4 addresses in the hosts file
  --no-ipv6             Do not enter IPv6 addresses in the hosts file
  --debug               Enable more verbose logging
  --no-cleanup          Skip cleaning up the hosts file on exit
```

## Credit

This was built upon the excellent work of David Darias on [docker-hoster](https://github.com/dvddarias/docker-hoster). 
I refactored the code, added tests & IPv6 support, and added the use CoreDNS.
