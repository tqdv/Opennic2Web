# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © 2021 Tilwa Qendov

# TODO redirect to the actual OpenNIC domain with Javascript
# TODO maybe add stats
# TODO add blocklist
# TODO recommend DNS over TLS or DNS over HTTPS
# TODO make use of twisted.web.template
# TODO convert logging to twisted.logging

        # # Remove connection specific headers
        # headers.removeHeader(b'connection')
        # headers.removeHeader(b'keep-alive')

# Debugging
import logging

import re
import zlib

from .opennic2web import OPENNIC_TLDS, parse_o2w_hostname, o2w_re, get_o2w_hostname, get_w2o_hostname
from .config import Config

from twisted.web import http, client, iweb
from twisted.web.http_headers import Headers
from twisted.internet import reactor, protocol, defer
from zope.interface import implementer # annotation, zope is required by twisted


# Inspired by twisted.web.proxy and Tor2Web
# cf. <https://twistedmatrix.com/documents/current/api/twisted.web.proxy.html>
# We don't subclass proxy.* as it hides control flow and it harder to work with


@implementer(iweb.IBodyProducer)
class CopyBodyProducer:
    """
    Produce the contents of the request to the new request ie. copy it

    Since we produce the body all at once, resumeProducing, pauseProducing
    and stopProducing do nothing.
    """
    
    def __init__(self, request):
        """
        @param request: The request to copy
        @type request: L{http.Request}
        """

        request.content.seek(0, 0)
        self.body = request.content.read()
        self.length = len(self.body)

    def startProducing(self, consumer):
        """
        We ignore the asynchronous behaviour and just copy it all at once
        """
        consumer.write(self.body)
        # Signal that we're done writing
        return defer.succeed(None)

    def resumeProducing(self):
        pass

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass


# === Protocols to handle the Opennic server response ===

class BodyCopyProtocol(protocol.Protocol):
    """
    Streams the response body back to the client

    Inspired by L{client._ReadBodyProtocol}
    """

    def __init__(self, request, deferred):
        """
        @param deferred: The Deferred object that gets trigerred when it is done copying
        """
        self.proxy_request = request
        self.deferred = deferred

    def dataReceived(self, data):
        self.proxy_request.write(data)

    def connectionLost(self, reason):
        if reason.check(client.ResponseDone):
            self.deferred.callback(True)
        else:
            self.deferred.errback(reason)


class HtmlBannerProtocol(protocol.Protocol):
    """
    TODO edit docs, please document
    Streams the response body back to the client

    Inspired by L{client._ReadBodyProtocol}
    """

    def __init__(self, original, banner, config, bufsize=1024):
        """
        @param original: The protocol to wrap
        """
        self.original = original
        self.banner = banner
        self.config = config

        self.bufsize = bufsize
        self._buffer = b''
        self.banner_inserted = False

    def dataReceived(self, data):
        # NB Although there are streaming regex engines (like intel's hyperscan),
        #    it's just simpler to assume there's a max URL size, and use
        #    a buffer that's larger than it

        data = self._buffer + data

        # Wait for enough data so we can completely replace the buffer.
        # NB This is a bit arbitrary, but whatever
        if not len(data) >= self.bufsize * 2:
            # Buffer data
            self._buffer = data
            return
        
        editedData = self.editHtml(data)

        # Forward the edited data, and keep a buffer
        forwardData = editedData[:-self.bufsize]
        self._buffer = editedData[-self.bufsize:]
        self.original.dataReceived(forwardData)
            

    def connectionLost(self, reason):
        # Flush buffer
        if self._buffer:
            editedData = self.editHtml(self._buffer)
            # TODO Should we insert the banner if it hasn't been done yet ?
            self.original.dataReceived(editedData)
            self._buffer = b''
        
        self.original.connectionLost(reason)
    
    
    def editHtml(self, data):
        # Insert banner
        if not self.banner_inserted:
            data = re.sub(o2w_re['body'], lambda m: m.group(0) + self.banner, data)
            self.banner_inserted = True

        # Rewrite URLs
        if self.config.rewrite_visible_url:
            data = re.sub(o2w_re['o2w'], lambda m: get_o2w_hostname(m, self.config), data)
        else:
            data = re.sub(o2w_re['html_o2w'], lambda m: get_o2w_hostname(m, self.config), data)

        return data


# TODO what does taking in response and raising errors do ?
class GzipDecompressor(protocol.Protocol):
    """
    Protocol that wraps another protocol by decompressing the input,
    and forwarding it to the wrapper protocol

    Copy pasted from L{twisted.web.client._GzipProtocol} but without the weird
    proxyForInterface magic and actually public

    @ivar _zlibDecompress: A zlib decompress object used to decompress the data
                           stream.
    @ivar _response: A reference to the original response, in case of errors.
    """

    def __init__(self, protocol, response):
        self.original = protocol
        self._response = response
        self._zlibDecompress = zlib.decompressobj(16 + zlib.MAX_WBITS)


    def dataReceived(self, data):
        """
        Decompress C{data} with the zlib decompressor, forwarding the raw data
        to the original protocol.
        """
        try:
            rawData = self._zlibDecompress.decompress(data)
        except zlib.error:
            raise ResponseFailed([Failure()], self._response)
        if rawData:
            self.original.dataReceived(rawData)


    def connectionLost(self, reason):
        """
        Forward the connection lost event, flushing remaining data from the
        decompressor if any.
        """
        try:
            rawData = self._zlibDecompress.flush()
        except zlib.error:
            raise ResponseFailed([reason, Failure()], self._response)
        if rawData:
            self.original.dataReceived(rawData)
        self.original.connectionLost(reason)


# TODO what does taking in response and raising errors do ?
class GzipCompressor(protocol.Protocol):
    """
    Protocol that wraps another protocol by compressing the input,
    and forwarding it to the wrapper protocol

    Copy pasted from L{GzipDecompresor}

    @ivar _zlibCompress: A zlib compress object used to decompress the data
                         stream.
    @ivar _response: A reference to the original response, in case of errors.
    """

    def __init__(self, protocol, response):
        self.original = protocol
        self._response = response
        self._zlibCompress = zlib.compressobj(wbits = 16 + zlib.MAX_WBITS)


    def dataReceived(self, data):
        """
        Compress C{data} with the zlib compressor, forwarding the raw data
        to the original protocol.
        """
        try:
            rawData = self._zlibCompress.compress(data)
        except zlib.error:
            raise ResponseFailed([Failure()], self._response)
        if rawData:
            self.original.dataReceived(rawData)


    def connectionLost(self, reason):
        """
        Forward the connection lost event, flushing remaining data from the
        compressor if any.
        """
        try:
            rawData = self._zlibCompress.flush()
        except zlib.error:
            raise ResponseFailed([reason, Failure()], self._response)
        if rawData:
            self.original.dataReceived(rawData)
        self.original.connectionLost(reason)

# ===...===

class Opennic2WebRequest(http.Request):
    """
    Our twisted Request ie. request handler, based on L{twisted.web.proxy.ProxyRequest}

    @ivar config: the Opennic2Web configuration object
    @ivar reactor: the reactor used to create connections.
    @type reactor: object providing L{twisted.internet.interfaces.IReactorTCP}
    """

    # TODO add HTTP/2 client

    def __init__(self, channel, queued=http._QUEUED_SENTINEL, reactor=reactor, http_pool=None):
        super().__init__(channel, queued)
        self.reactor = reactor
        self.config = channel.config
        self.http_pool = http_pool

    # TODO handle user@passwd:domain.tld properly
    def process(self):
        """
        Handle the request by either proxying the request to the requested OpenNIC domain, or our
        own error message
        """
        defer.ensureDeferred(self.asyncProcess())
    
    async def asyncProcess(self):
        # === Check if we should proxy the request ===

        hostname = self.getRequestHostname()
        (domain, subdomains, tld, port) = parse_o2w_hostname(hostname, self.config)

        if not domain:
            # No subdomain requested
            self.setResponseCode(http.NOT_IMPLEMENTED) # FIXME
            # TODO serve homepage
            self.finish()
            return

        if not subdomains:
            # TLD directly requested
            self.setResponseCode(http.NOT_FOUND)
            # TODO add html body
            self.finish()
            return
        
        # Reject blocked domains
        if self.config.should_block_domain(domain):
            self.setResponseCode(http.FORBIDDEN)
            # TODO display blocked domain html
            self.finish()
            return

        # Prevent indexing a proxied page
        if self.uri == b'/robots.txt':
            self.responseHeaders.addRawHeader(b'content-type', b'text/plain')
            self.write(b'User-agent: *\nDisallow: /\n')
            self.finish()
            return
        
        # Compute destination URL
        protocol = b'https' if self.isSecure() else b'http'
        port_suffix = b':%d' % (port) if port is not None else b''
        url = protocol + b'://' + domain + port_suffix + self.uri
        
        # Redirect ICANN TLDs to their normal URLs
        if tld not in OPENNIC_TLDS:
            self.setResponseCode(http.FOUND)
            self.setHeader(b"location", url)
            self.finish()
            return
        
        # Prevent hotlinking (naive implementation)
        origin_line = self.requestHeaders.getRawHeaders(b'origin', [b''])[0]
        if self.config.should_block_hotlink(domain, self.uri, origin_line):
            self.setResponseCode(http.FORBIDDEN)
            # TODO add html body
            self.finish()
            return

        # === Checks done, we're sending a request to the "OpenNIC server" ===

        via_line = self.clientproto + b' Opennic2Web'
        forwarded_line = b'by=%b;for=_hidden;host=%b;proto=%b' % (self.config.hostname, hostname, protocol)

        # Rewrite headers
        headers = self.requestHeaders.copy()
        headers.setRawHeaders(b'host', [domain + port_suffix])
        referer_line = headers.getRawHeaders(b'referer', [None])[0]
        if referer_line is not None:
            new_referer = re.sub(self.config.re_header_w2o, lambda m: get_w2o_hostname(m), referer_line)
            headers.setRawHeaders(b'referer', [new_referer])
        origin_line = headers.getRawHeaders(b'origin', [None])[0]
        if origin_line is not None:
            new_origin = re.sub(self.config.re_header_w2o, lambda m: get_w2o_hostname(m), origin_line)
            headers.setRawHeaders(b'origin', [new_origin])

        # Add forwarding headers
        headers.addRawHeader(b'via', via_line)
        headers.addRawHeader(b'x-forwarded-host', hostname)
        headers.addRawHeader(b'x-forwarded-proto', protocol)
        headers.addRawHeader(b'forwarded', forwarded_line)
        # The Content-Length header is handled by agent through body_producer

        # NB \xe2\x86\x92 is the UTF-8 encoding of '→' 
        logging.debug((
            b"[%b] \xe2\x86\x92 %b %b" % (hostname, self.method, url)
        ).decode(errors='replace'))

        # Create our Agent and send the request
        agent = client.Agent(self.reactor, pool=self.http_pool)
        response = await agent.request(self.method, url, headers=headers, bodyProducer=CopyBodyProducer(self))

        # TODO handle failed request
        
        # === Process the response ===

        # Copy response headers and status code
        self.setResponseCode(response.code)
        self.responseHeaders = response.headers.copy()
        self.responseHeaders.addRawHeader(b'via', via_line)

        # Rewrite headers
        location_line = self.responseHeaders.getRawHeaders(b'location', [None])[0]
        if location_line is not None:
            new_location = re.sub(o2w_re['header_o2w'], lambda m: get_o2w_hostname(m, self.config), location_line)
            self.responseHeaders.setRawHeaders(b'location', [new_location])
        # TODO rewrite CORS header

        # NB \xe2\x86\x90 is the UTF-8 encoding of '←'
        logging.debug((b"\xe2\x86\x90 %b %b" % (self.method, url)).decode(errors='replace'))

        # We create our BodyProtocol pipeline, the last one is always BodyCopy
        # The protocols are "executed" from left to right
        body_pipeline = []

        content_type = response.headers.getRawHeaders(b'content-type', default=[b''])[0]
        # NB I know the syntax is not readable but trust me, it works
        content_encoding = [ value.strip()
            for line in response.headers.getRawHeaders(b'content-encoding', [])
            for value in line.split(b',') ] # TODO move to util probably
        response_is_gzipped = [b'gzip'] == content_encoding

        # Insert banner in HTML pages
        # NB CSS and JS (and others) can contain (absolute) URLs, but it
        #    should be rare enough to be safe to ignore
        if content_type and b'text/html' in content_type:
            # Gzip decompress if it is the only compression (this is not "correct", but should be good enough)
            if response_is_gzipped:
                content_encoding = []
                body_pipeline.append(lambda x: GzipDecompressor(x, response))
                self.responseHeaders.removeHeader(b'content-encoding')
                self.responseHeaders.removeHeader(b'content-length')
                response_is_gzipped = False
            
            # Modify the HTML if it's now in plaintext
            if not content_encoding:
                body_pipeline.append(lambda x: HtmlBannerProtocol(x, self.channel.factory.banner, self.config))

        # Gzip compress the response based on its mime type and if the client supports it and if it's not redundant
        if (content_type and not content_encoding
        and b'gzip' in self.requestHeaders.getRawHeaders(b'accept-encoding', [b''])[0]
        and self.config.should_gzip_content(content_type)):
            body_pipeline.append(lambda x: GzipCompressor(x, response))
            self.responseHeaders.addRawHeader(b'content-encoding', b'gzip')
        
        # Send response back to client processed through body_pipeline
        write_body = defer.Deferred() # fires when the response has been completely written to the client
        body_protocol = BodyCopyProtocol(self, write_body)
        for pipe_elt in reversed(body_pipeline):
            body_protocol = pipe_elt(body_protocol)
        response.deliverBody(body_protocol)
        await write_body

        # TODO handle failed write_body (and a bunch of body_protocol errors)
        #      eg. timeout and NXDOMAINs

        logging.debug((b"%b %b \xe2\x86\x90" % (self.method, url)).decode(errors='replace'))

        self.finish()


# TODO look into http._GenericHTTPChannelProtocol to automatically switch on HTTP2
class Opennic2Web(http.HTTPChannel):
    """
    Our twisted Protocol ie. connection handler

    @ivar config: the Opennic2Web configuration object
    """

    def _pooledOpennic2WebRequest(self, *args, **kwargs):
        return Opennic2WebRequest(*args, **kwargs, http_pool=self.http_pool)

    requestFactory = _pooledOpennic2WebRequest

    def __init__(self, config, http_pool=None):
        super().__init__()
        self.config = config
        self.http_pool = http_pool


# TODO would inheriting from Site be more interesting to use Ressources abstractions ?
class Opennic2WebFactory(http.HTTPFactory):
    """
    Our twisted protocol.Factory ie. the server

    Synopsis:

        reactor.listenTCP(8080, Opennic2WebFactory())
        reactor.run()
    
    @ivar config: the Opennic2Web configuration object
    """

    def _configured_and_pooledOpennic2WebFactory(self):
        """
        Returns a configured Opennic2WebFactory. Used in Opennic2WebFactory.
        """
        return Opennic2Web(self.config, http_pool=self.http_pool)

    protocol = _configured_and_pooledOpennic2WebFactory

    def __init__(self, config=None, reactor=reactor):
        if config is None:
            raise ValueError("Missing configuration")

        super().__init__()
        self.config = config
        self.http_pool = client.HTTPConnectionPool(reactor)
        # TODO refactor path to config
        with open('templates/banner.xml', 'rb') as f:
            self.banner = f.read()
