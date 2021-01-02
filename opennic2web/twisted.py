# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © 2021 Tilwa Qendov

# TODO Allow streaming the OpenNIC response to the client cf. CopyBodyProducer and maybe .endHeaders to early redirect
# TODO add banner
# TODO redirect to the actual OpenNIC domain with Javascript
# TODO check if the client is a crawler
# TODO gzip responses if we can (on certain mimetypes ?)
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

from .opennic2web import OPENNIC_TLDS, parse_o2w_hostname
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

    Since we produce the body all at once, resumeProducing, pauseProducing and stopProducing do nothing.
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
        (domain, subdomains, tld, port) = parse_o2w_hostname(self.getRequestHostname(), self.config)

        if not domain:
            # No subdomain requested
            todo()
            self.finish()
            return

        if not subdomains:
            # TLD directly requested
            todo()
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
        if self.uri.lower().endswith(tuple(self.config.block_hotlink_exts)):
            for referer in self.requestHeaders.getRawHeaders(b'referer', []):
                if domain not in referer.lower():
                    self.setResponseCode(error)
                    todo()
                    self.finish()
                    return

        # === Checks done, we're sending a request to the OpenNIC server ===

        via_line = self.clientproto + b' Opennic2Web'

        # Rewrite headers
        headers = self.requestHeaders.copy()
        headers.setRawHeaders(b'host', [domain + port_suffix])
        headers.addRawHeader(b'via', via_line)
        # The Content-Length header is handled by agent through body_producer
        # TODO Transfer-Encoding ? what about them ? cf. T2W

        # \xe2\x86\x92 is the UTF-8 encoding of '→' 
        logging.debug((
            b"[%b] \xe2\x86\x92 %b %b" % (self.getRequestHostname(), self.method, url)
        ).decode(errors='replace'))

        # TODO Do we need to implement EndpointFactory or something cf. T2W
        # Create our Agent and send the request
        agent = client.Agent(self.reactor) # pool=self.http_pool
        response = await agent.request(self.method, url, headers=headers, bodyProducer=CopyBodyProducer(self))

        # TODO handle failed request
        
        # === Process the response ===

        self.setResponseCode(response.code)
        self.responseHeaders = response.headers.copy()
        self.responseHeaders.addRawHeader(b'via', via_line)

        # \xe2\x86\x90 is the UTF-8 encoding of '←'
        logging.debug((b"\xe2\x86\x90 %b %b" % (self.method, url)).decode(errors='replace'))

        # A Deferred that fires when the response has been completely written to the client
        write_body = defer.Deferred()
        body_protocol = None

        # v TODO Should we try to handle deflate ?
        # client.GzipDecoder
        
        # TODO optionally compress the response

        # Insert banner in HTML pages
        # NB CSS and JS (and others) can contain (absolute) URLs, but it
        #    should be rare enough to be safe to ignore
        if b'text/html' in self.responseHeaders.getRawHeaders(b'content-type', default=[b''])[0]:
            logging.debug(f"{self.uri.decode()} is HTML")

            # LEFTOF decompress if needed

            # TODO actually modify the HTML (and decompress when needed)
            body_protocol = None
        
        if body_protocol is None:
            body_protocol = BodyCopyProtocol(self, write_body)
        
        # Send response back to client processed through body_protocol
        response.deliverBody(body_protocol)
        await write_body

        # TODO handle failed write_body

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

    def __init__(self, config=Config(), reactor=reactor):
        super().__init__()
        self.config = config
        self.http_pool = client.HTTPConnectionPool(reactor)
