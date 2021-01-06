# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © 2021 Tilwa Qendov

import re
from .util import remove_suffix

OPENNIC_TLDS = b"bbs chan cyb dyn epic geek gopher indy libre neo null o oss oz parody pirate".split()
OPENNIC_TLDS_RE = b'|'.join(OPENNIC_TLDS)


def parse_o2w_hostname(host, config):
    """
    Parse the hostname into the target domain, subdomains, tld, and port.

    Examples
        host = b'be.libre.opennic2web.com' -> (b'be.libre', b'be', b'libre', None)
        host = b'cyb.8080.opennic2web.com' -> (b'cyb', b'', b'cyb', 8080)
        host = b'reg.geek.80000.opennic2web.com' -> (b'reg.geek.80000', b'reg.geek', b'80000', None)
        

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


# TODO add custom port
def get_o2w_hostname(match, config):
    """
    Return the translated Opennic2Web url from the o2w regex match.
    Also for the html_o2w regex
    """
    port = match.group(3)
    port = b'.' + port if port else b''

    return match.group(1) + port + b'.' + config.hostname


o2w_re = {
    'body': re.compile(b'<body.*?>', re.I),
    # NB This doesn't handle domains with a trailing dot eg. opennic.oss.
    #    This parses wrongly if the string cuts off just before the port suffix eg. opennic.oss[CUT]:8080 
    #    This parses wrongly if the string cuts off just after a valid tld eg. opennic.o[CUT]bject
    #    This parses wrongly if the port number is invalid eg. opennic.o:1234567 => port = 12345
    # See <https://stackoverflow.com/a/48611406/5226686> for (?= (?P<...>) ) (?P=...)
    'o2w': re.compile(rb'''
        (
            # (?: http: | https: )?         # Protocol
            //
            (?= (?P<subdomains> (?: [a-zA-Z0-9-]{1,63} \. )+ ) ) (?P=subdomains) # Non-backtracking Subdomains $2
            (?: ''' + OPENNIC_TLDS_RE + rb''' ) # TLD
            (?! \. | [a-zA-Z0-9-] ) # Not a subdomain or the start of a label
        )                           # Domain name $1
        (?: : (\d{1,5}) )?          # Port number $3?
        ''', re.X),
    'html_o2w': re.compile(rb'''
        (
            # (archive|background|cite|classid|codebase|data|formaction|href|icon|longdesc|manifest|poster|profile|src|url|usemap|)
            = ['"]?
            (?: http: | https: )?   # Protocol
            //
            (?= (?P<subdomains> (?: [a-zA-Z0-9-]{1,63} \. )+ ) ) (?P=subdomains) # Non-backtracking Subdomains $2
            (?: ''' + OPENNIC_TLDS_RE + rb''' ) # TLD
            (?! \. | [a-zA-Z0-9-] ) # Not a subdomain or the start of a label
        )                           # Domain name (and prefix) $1
        (?: : (\d{1,5}) )?          # Port number $3?
        ''', re.X),
}