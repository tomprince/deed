from __future__ import print_function, absolute_import

from twisted.python import usage
from twisted.internet.defer import maybeDeferred, inlineCallbacks
from twisted.python.filepath import FilePath

from deed.authority import (
        generateKey, generateCertificateRequest,
        CertificateStore, RemoteCertificateStore)
from twisted.internet.ssl import KeyPair
from twisted.internet.endpoints import clientFromString


@inlineCallbacks
def newKey(config):
    subject = config['subject']
    path = config['path']

    store = yield config.parent.storeDeferred

    key = generateKey()
    path.setContent(key.dumpPEM())

    req = generateCertificateRequest(key, subject)
    yield store.submitCertificateRequest(req)

@inlineCallbacks
def requestCert(config):
    subject = config['subject']
    path = config['path']

    store = yield config.parent.storeDeferred

    key = KeyPair.loadPEM(path.getContent())
    req = generateCertificateRequest(key, subject)
    yield store.submitCertificateRequest(req)


@inlineCallbacks
def getCert(config):
    subject = config['subject']
    path = config['path']

    store = yield config.parent.storeDeferred

    cert = yield store.getCertificate(subject)
    path.setContent(cert.dumpPEM())
    path.chmod(0o644)


class NewKeyOptions(usage.Options):
    run = newKey

    def parseArgs(self, subject, path):
        self['subject'] = subject
        self['path'] = FilePath(path)


class RequestCertOptions(usage.Options):
    run = requestCert

    def parseArgs(self, subject, path):
        self['subject'] = subject
        self['path'] = FilePath(path)


class GetCertOptions(usage.Options):
    run = getCert
    def parseArgs(self, subject, path):
        self['subject'] = subject
        self['path'] = FilePath(path)



from twisted.internet import reactor
from functools import partial
class Options(usage.Options):
    synopsis = ""

    optParameters = [['path', 'd', None, 'Path to CA.', FilePath],
                     ['port', 'p', None, 'Port for CA.', partial(clientFromString, reactor)]
                     ]
    subCommands = [['new-key', '', NewKeyOptions, ''],
                   ['request-cert', '', RequestCertOptions, ''],
                   ['get-cert', '', GetCertOptions, ''],
                   ]
    optFlags = [['verbose', 'v']]

    def postOptions(self):
        if self['verbose']:
            from twisted.python.log import startLogging
            import sys
            startLogging(sys.stdout)
        if self['path']:
            self.storeDeferred = maybeDeferred(CertificateStore.fromFilePath, self['path'])
        elif self['port']:
            self.storeDeferred = RemoteCertificateStore.fromEndpoint(self['port'])
        else:
            raise usage.UsageError('Must specify path or port')



def main(reactor, *argv):
    config = Options()
    config.parseOptions(argv[1:])
    return maybeDeferred(config.subOptions.run)
