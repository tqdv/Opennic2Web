#!/usr/bin/env python3

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © 2021 Tilwa Qendov

import logging
import argparse

from opennic2web import Opennic2WebFactory, Config

from twisted.internet import reactor
from twisted.internet.endpoints import serverFromString
from twisted.logger import globalLogPublisher, STDLibLogObserver

# === Parse command-line arguments

parser = argparse.ArgumentParser()
parser.add_argument("--twisted", help="Turn on twisted logging")
args = parser.parse_args()


logging.basicConfig(level = logging.DEBUG, format = '%(levelname)s %(filename)s:%(lineno)d | %(message)s')
if args.twisted:
	globalLogPublisher.addObserver(STDLibLogObserver())

config = Config(hostname = b'localhost')
factory = Opennic2WebFactory(config=config)

http_server = serverFromString(reactor, 'tcp:8080')
http_server.listen(factory)

#https_server = serverFromString(reactor, 'ssl:8443:privateKey=key.pem:certKey=crt.pem')
#https_server.listen(factory)

print("Ready")
reactor.run()