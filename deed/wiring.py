# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Components for connecting responder code to AMP and JSON-RPC network
transports.
"""

from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory
from twisted.internet.endpoints import serverFromString
from twisted.application.service import Service
from twisted.protocols import amp

class AMPFactory(ServerFactory):
    """
    Factory for listening for AMP requests.

    @param responder: An object that provides responders to AMP
    commands.
    """
    def __init__(self, responder):
        self.responder = responder


    def buildProtocol(self, addr):
        disp = amp.BoxDispatcher(self.responder)
        a = amp.AMP(boxReceiver=disp, locator=self.responder)
        a.factory = self
        return a



class AMPService(Service):
    """
    Service for AMP listener.

    @param port: An endpoint description, suitable for
    `serverToString`.

    @param responder: An object providing responders for AMP commands.
    """
    def __init__(self, port, responder):
        self.port = port
        self.responder = responder


    def startService(self):
        self.endpoint = serverFromString(reactor, self.port)
        self.endpoint.listen(AMPFactory(self.responder))
