#!/usr/bin/env python3

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © 2021 Tilwa Qendov

import logging
from twisted.internet import reactor
from opennic2web import Opennic2WebFactory, Config

logging.basicConfig(level = logging.DEBUG, format = '%(levelname)s %(filename)s:%(lineno)d %(message)s')

# TODO use twisted endpoints cf. <https://twistedmatrix.com/documents/current/core/howto/endpoints.html>
config = Config(hostname = b'localhost')
reactor.listenTCP(8080, Opennic2WebFactory(config=config))

print("Ready")
reactor.run()