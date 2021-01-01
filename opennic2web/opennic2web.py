#!/usr/bin/env python3

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © 2021 Tilwa Qendov

# TODO add banner
# TODO redirect to the actual OpenNIC domain with Javascript
# TODO check if the client is a crawler
# TODO gzip responses if we can (on certain mimetypes ?)
# TODO maybe add stats
# TODO prevent hotlinking
# TODO add blocklist
# TODO recommend DNS over TLS or DNS over HTTPS

# Debugging
from pprint import pprint as pp
import logging

from .util import remove_suffix
from .config import Config

from twisted.web import http, proxy
from twisted.web.http_headers import Headers
from twisted.internet import reactor, protocol

OPENNIC_TLDS = b"bbs chan cyb dyn epic geek gopher indy libre neo null o oss oz parody pirate".split()

# Inspired by twisted.web.proxy and Tor2Web
# cf. <https://twistedmatrix.com/documents/current/api/twisted.web.proxy.html>
# We don't subclass proxy.* as it hides control flow and it harder to work with

# TODO why does Tor2Web subclass client.Agent instead ?
class Opennic2WebClient(http.HTTPClient):
    """
    Our outgoing client ie. HTTP client

    It naively copies headers and transfers data from the server to the client, without looking at it.

    @ivar _finished: A flag which indicates whether or not the original request
        has been finished yet.
    """
    _finished = False

    def __init__(self, command, uri, _version, headers, data, proxy_request):
        """
        @param headers: The headers the client sends to the server
        @type headers: a L{Headers} object
        """

        self.proxy_request = proxy_request
        self.responseHeaders = proxy_request.responseHeaders
        self.command = command
        self.uri = uri

        # Remove connection specific headers
        headers.removeHeader(b'connection')
        headers.removeHeader(b'keep-alive')

        self.headers = headers
        self.data = data


    def connectionMade(self):
        """
        Send the HTTP request after the connection is established
        """
        self.sendCommand(self.command, self.uri)
        for header, values in self.headers.getAllRawHeaders():
            for v in values:
                self.sendHeader(header, v)
        self.endHeaders()
        self.transport.write(self.data)

    def handleStatus(self, version, code, message):
        """
        Copy HTTP status code to the original proxy request
        """
        self.proxy_request.setResponseCode(int(code), message)


    def handleHeader(self, key, value):
        """
        Copy received headers to the original proxy Request
        """
        self.responseHeaders.addRawHeader(key, value)
    
    def handleEndHeaders(self):
        """
        Add custom headers after the server is done with theirs
        """
        self.responseHeaders.addRawHeader(b'via', b'Opennic2Web')

    def handleResponsePart(self, buffer):
        """
        Progressively write response back to the original proxy request client
        """
        self.proxy_request.write(buffer)

    # This function can be called multiple times cf. twisted doc, hence the instance state variable _finished
    def handleResponseEnd(self):
        """
        Finish the original request, indicating that the response has been
        completely written to it, and disconnect the outgoing transport.
        """
        if not self._finished:
            self._finished = True
            self.proxy_request.finish()
            self.transport.loseConnection()


class Opennic2WebClientFactory(protocol.ClientFactory):
    """
    Our ClientFactory to handle Requests. We mostly copy constructor variables.
    """

    protocol = Opennic2WebClient

    def __init__(self, command, uri, version, headers, data, proxy_request):
        self.proxy_request = proxy_request
        self.command = command
        self.uri = uri
        self.version = version
        self.headers = headers
        self.data = data

    def buildProtocol(self, addr):
        return self.protocol(
            self.command, self.uri, self.version,
            self.headers, self.data, self.proxy_request
        )

    # TODO templatize
    def clientConnectionFailed(self, connector, reason):
        """
        Report a connection failure in a response to the incoming request as
        an error.
        """
        self.proxy_request.setResponseCode(501, b"Gateway error")
        self.proxy_request.responseHeaders.addRawHeader(b"Content-Type", b"text/html")
        self.proxy_request.write(b"<H1>Could not connect</H1>")
        self.proxy_request.finish()

# TODO move in another file
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

    label = last_or_none(parts) # The last element in parts or None

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


class Opennic2WebRequest(http.Request):
    """
    Our twisted Request ie. request handler, based on L{twisted.web.proxy.ProxyRequest}

    @ivar config: the Opennic2Web configuration object
    @ivar reactor: the reactor used to create connections.
    @type reactor: object providing L{twisted.internet.interfaces.IReactorTCP}
    """

    # TODO add HTTPS clients
    protocols = {b'http': Opennic2WebClientFactory}
    ports = {b'http': 80}

    def __init__(self, channel, queued=http._QUEUED_SENTINEL, reactor=reactor):
        super().__init__(channel, queued)
        self.reactor = reactor
        self.config = channel.config

    # TODO handle user@passwd:domain.tld properly
    def process(self):
        """
        Handle the request by either proxying the request to the requested OpenNIC domain, or our
        own error message
        """
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
        
        # Redirect ICANN TLDs to their normal URLs
        if tld not in OPENNIC_TLDS:
            self.setResponseCode(http.FOUND)
            port_bytes = b':%d' % (port) if port is not None else b''
            url = b''.join([protocol, b'://', domain, port_bytes, self.uri])
            self.setHeader(b"location", url)
            self.finish()
            return
        
        # Prevent hotlinking (naive implementation)
        if self.uri.lower().endswith(tuple(self.config.block_hotlink_exts)):
            for referer in self.requestHeaders.getRawHeaders(b'referer', []):
                if domain not in referer.lower():
                    self.sendError(403)
                    return

        # Rewrite headers
        headers = self.requestHeaders.copy()
        headers.setRawHeaders(b'host', [domain])
        headers.addRawHeader(b'via', b'Opennic2Web')

        self.content.seek(0, 0)
        data = self.content.read()

        protocol = b'https' if self.isSecure() else b'http'
        conn_port = port if port is not None else self.ports[protocol]

        clientFactory = self.protocols[protocol](
            self.method, self.uri, self.clientproto,
            headers, data, self
        )
        self.reactor.connectTCP(domain, conn_port, clientFactory)
        # The client will call .finish() for us


# TODO look into http._GenericHTTPChannelProtocol to automatically switch on HTTP2
class Opennic2Web(http.HTTPChannel):
    """
    Our twisted Protocol ie. connection handler

    @ivar config: the Opennic2Web configuration object
    """

    requestFactory = Opennic2WebRequest

    def __init__(self, config):
        super().__init__()
        self.config = config

# TODO would inheriting from Site be more interesting to use Ressources abstractions ?
class Opennic2WebFactory(http.HTTPFactory):
    """
    Our twisted protocol.Factory ie. the server

    Synopsis:
        # TODO
        reactor.listenTCP(8080, Opennic2WebFactory(config))
        reactor.run()
    
    @ivar config: the Opennic2Web configuration object
    """

    def _configuredOpennic2WebFactory(self):
        """
        Returns a configured Opennic2WebFactory. Used in Opennic2WebFactory.
        """
        return Opennic2Web(self.config)

    protocol = _configuredOpennic2WebFactory

    # TODO add default config ?
    def __init__(self, config=Config()):
        super().__init__()
        self.config = config
