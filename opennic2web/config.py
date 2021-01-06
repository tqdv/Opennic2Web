# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © 2021 Tilwa Qendov

# TODO add checking methods

class Config:
    """
    The Opennic2Web configuration object

    @ivar hostname: The domain name on which opennic2web is run eg. b'opennic2web.com'
    @type hostname: A byte string

    @ivar block_hotlink_exts: The extensions to block for hotlinking eg. [b'png', b'jpg']

    @ivar gzip_mimetypes: The Content-Types to compress if we can eg. [b'text/html', b'text/css']
    """
    def __init__(self,
        hostname = b'localhost', # FIXME change default hostname
        block_hotlink_exts = b'jpg png gif'.split(),
        gzip_mimetypes = b'text/html text/xml application/xhtml+xml text/plain text/javascript text/css image/svg+xml'.split(),
        rewrite_visible_url = False
        ):
        self.hostname = hostname
        self.block_hotlink_exts = block_hotlink_exts
        self.gzip_mimetypes = gzip_mimetypes
        self.rewrite_visible_url = rewrite_visible_url
    
    def should_gzip_content(self, content_type):
        """
        Returns if you should gzip the given Content-Type
        """
        for mime_type in self.gzip_mimetypes:
            if mime_type in content_type:
                return True
        return False

    def should_block_hotlink(self, domain, uri, referrers):
        """
        Returns if the URI should be blocked to prevent hotlinking
        """
        if uri.lower().endswith(tuple(self.block_hotlink_exts)):
            for referer in referrers:
                if domain not in referer.lower():
                    return True
        return False
