#!/usr/bin/env python3

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © 2021 Tilwa Qendov

# Debugging
from pprint import pprint as pp
import logging

from .util import remove_suffix

from twisted.web import http, proxy
from twisted.internet import reactor

# Inspired by twisted.web.proxy and Tor2Web
# cf. <https://twistedmatrix.com/documents/current/api/twisted.web.proxy.html>

# TODO why does Tor2Web subclass http.Client instead ?
class Opennic2WebClient(proxy.ProxyClient):
    """
    Our outgoing client ie. HTTP client
    """
    pass


class Opennic2WebClientFactory(proxy.ProxyClientFactory):
    """
    Our ClientFactory to handle Requests.
    """
    
    protocol = Opennic2WebClient


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
        super().__init__(channel)
        self.reactor = reactor
        self.config = channel.config

    def process(self):
        protocol = self.getProtocol()
        # TODO handle case where the hostname is invalid eg there is no subdomain
        # TODO Do we always remove the trailing dot ? eg. example.com. vs. example.com
        host = remove_suffix(self.getRequestHostname(), b'.' + self.config.hostname)
        port = self.ports[protocol]
        # TODO handle custom ports

        assert (protocol and host), "Strings are not empty"

        # TODO T2W had a .copy() here, is it needed ?
        headers = self.getAllHeaders() # returns lowercased header keys 
        headers[b'host'] = host

        self.content.seek(0, 0)

        # TODO understand
        clientFactory = self.protocols[protocol](
            self.method, self.uri, self.clientproto, headers, self.content.read(), self
        )

        self.reactor.connectTCP(host, port, clientFactory)
    
    def getProtocol(self):
        """
        Returns the request protocol as a byte string
        """
        return b'https' if self.isSecure() else b'http'


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
