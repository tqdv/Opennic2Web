# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © 2021 Tilwa Qendov

from .util import remove_suffix

OPENNIC_TLDS = b"bbs chan cyb dyn epic geek gopher indy libre neo null o oss oz parody pirate".split()


def parse_o2w_hostname(host, config):
    """
    Parse the hostname into the target domain, subdomains, tld, and port.

    If the port is not present, it is set to None.
    If domain, subdomains or tld are not present, they are set to the empty byte string.
    """
    def last_or_none(l):
        try:
            return l[-1]
        except:
            return None
    
    (tld, port) = (b'', None)
    
    host = remove_suffix(host, config.hostname)
    host = remove_suffix(host, b'.')
    
    parts = host.rsplit(b'.', 2)

    label = last_or_none(parts)

    # Parse *.<port>.opennic2web
    if label is not None and label.isdigit():
        maybe_port = int(label)
        if maybe_port <= 65535:
            port = maybe_port
            parts.pop()
            label = last_or_none(parts)
    
    # Copy domain before we parse the tld
    domain = b'.'.join(parts)

    # Parse *.<tld>.opennic2web
    if label is not None:
        tld = label
        parts.pop()
    
    subdomains = b'.'.join(parts)
    
    return (domain, subdomains, tld, port)
