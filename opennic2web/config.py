# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © 2021 Tilwa Qendov

import hashlib
import re
from .opennic2web import OPENNIC_TLDS_RE

class Config:
    """
    The Opennic2Web configuration object

    @ivar hostname: The domain name on which opennic2web is run eg. b'opennic2web.com'
    @type hostname: A byte string

    @ivar block_hotlink_exts: The extensions to block for hotlinking eg. [b'png', b'jpg']

    @ivar gzip_mimetypes: The Content-Types to compress if we can eg. [b'text/html', b'text/css']
    """
    def __init__(self, hostname = None,
                 block_hotlink_exts = None,
                 gzip_mimetypes = None,
                 rewrite_visible_url = False,
                 blocklist = None):
        if hostname is None:
            raise ValueError("Missing hostname")

        self.hostname = hostname
        self.block_hotlink_exts = block_hotlink_exts if block_hotlink_exts is not None else b'jpg png gif'.split()
        self.gzip_mimetypes = gzip_mimetypes if gzip_mimetypes is not None else b'text/html text/xml application/xhtml+xml text/plain text/javascript text/css image/svg+xml'.split()
        self.rewrite_visible_url = rewrite_visible_url
        self.blocklist = blocklist if blocklist is not None else []

        # TODO handle custom ports
        self.re_header_w2o = re.compile(rb'''
            (
                //
                (?= (?P<subdomains> (?: [a-zA-Z0-9-]{1,63} \. )+ ) ) (?P=subdomains) # Non-backtracking Subdomains $2
                (?: ''' + OPENNIC_TLDS_RE + rb''' ) # TLD
            )                       # Domain name $1
            (?: \. ( \d{1,5} ) )?   # Port $3?
            \. ''' + re.escape(self.hostname) + rb'''
            (?! \. | [a-zA-Z0-9-] ) # Not an incomplete subdomain or label
            ''', re.X)
    
    def should_gzip_content(self, content_type):
        """
        Returns if you should gzip the given Content-Type
        """
        for mime_type in self.gzip_mimetypes:
            if mime_type in content_type:
                return True
        return False

    def should_block_hotlink(self, domain, uri, origin):
        """
        Returns if the URI should be blocked to prevent hotlinking
        """
        return (uri.lower().endswith(tuple(self.block_hotlink_exts))
                and origin and domain not in origin.lower())

    def should_block_domain(self, domain):
        labels = domain.split(b'.')
        for i in range(2, len(labels)+1):
            partial_domain = b'.'.join(labels[-i:])
            if hashlib.sha256(partial_domain) in self.blocklist:
                return True
        return False
