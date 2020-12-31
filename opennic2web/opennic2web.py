#!/usr/bin/env python3

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © 2021 Tilwa Qendov

# Debugging
from pprint import pprint as pp
import logging

from .util import remove_suffix

from twisted.web import http, proxy
from twisted.web.http_headers import Headers
from twisted.internet import reactor, protocol

OPENNIC_TLDS = b"bbs chan cyb dyn epic geek gopher indy libre neo null o oss oz parody pirate".split()

# Inspired by twisted.web.proxy and Tor2Web
# cf. <https://twistedmatrix.com/documents/current/api/twisted.web.proxy.html>
# We don't subclass proxy.* as it hides control flow and it harder to work with

# TODO add banner
# TODO why does Tor2Web subclass client.Agent instead ?
class Opennic2WebClient(http.HTTPClient):
    """
    Our outgoing client ie. HTTP client

    It copies headers and transfers data from the server to the client.

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

    def clientConnectionFailed(self, connector, reason):
        """
        Report a connection failure in a response to the incoming request as
        an error.
        """
        self.proxy_request.setResponseCode(501, b"Gateway error")
        self.proxy_request.responseHeaders.addRawHeader(b"Content-Type", b"text/html")
        self.proxy_request.write(b"<H1>Could not connect</H1>")
        self.proxy_request.finish()


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
        host = self.getRequestHostname()
        host = remove_suffix(host, self.config.hostname)
        host = remove_suffix(host, b'.')

        if not host:
            # No subdomain requested
            todo() 
            self.finish()
            return

        try:
            tld = host.rsplit(b'.', 1)[1]
        except:
            # TLD directly requested
            todo()
            self.finish()
            return
        
        protocol = b'https' if self.isSecure() else b'http'
        port = self.ports[protocol]
        # TODO handle custom ports somehow
        
        if tld not in OPENNIC_TLDS:
            # (Permanently) redirect to the normal url
            # self.setResponseCode(http.MOVED_PERMANENTLY)
            self.setResponseCode(http.FOUND)
            port_bytes = b':%d' % port if port != self.ports[protocol] else b''
            url = b''.join([protocol, b'://', host, port_bytes, self.uri])
            self.setHeader(b"location", url)
            self.finish()
            return

        # Rewrite headers
        headers = self.requestHeaders.copy()
        headers.setRawHeaders(b'host', [host])
        headers.addRawHeader(b'via', b'Opennic2Web')

        self.content.seek(0, 0)
        data = self.content.read()

        clientFactory = self.protocols[protocol](
            self.method, self.uri, self.clientproto,
            headers, data, self
        )
        self.reactor.connectTCP(host, port, clientFactory)
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
    def __init__(self, config):
        super().__init__()
        self.config = config
