#!/usr/bin/env python3

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright © 2021 Tilwa Qendov

import logging
import argparse

from opennic2web import Opennic2WebFactory, Config

from twisted.internet import reactor
from twisted.logger import globalLogPublisher, STDLibLogObserver

# === Parse command-line arguments

parser = argparse.ArgumentParser()
parser.add_argument("--twisted", help="Turn on twisted logging")
args = parser.parse_args()


logging.basicConfig(level = logging.DEBUG, format = '%(levelname)s %(filename)s:%(lineno)d | %(message)s')
if args.twisted:
	globalLogPublisher.addObserver(STDLibLogObserver())

# TODO use twisted endpoints cf. <https://twistedmatrix.com/documents/current/core/howto/endpoints.html> ... maybe ?
config = Config(hostname = b'localhost')
reactor.listenTCP(8080, Opennic2WebFactory(config=config))

print("Ready")
reactor.run()