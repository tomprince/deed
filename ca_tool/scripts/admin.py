from __future__ import print_function, absolute_import

from twisted.python import usage
from twisted.internet.defer import maybeDeferred
from twisted.python.filepath import FilePath

from ca_tool.authority import (
        CertificateStore)

def init(config):
    path = config['storePath']
    subject = config['subject']

    CertificateStore.newStore(path, subject)


def signRequest(config):
    subject = config['subject']

    store = config.parent.store

    store.signRequest(subject)




class InitOptions(usage.Options):
    run = init

    def parseArgs(self, subject):
        self['subject'] = subject


class SignRequestOptions(usage.Options):
    run = signRequest

    def parseArgs(self, subject):
        self['subject'] = subject


class Options(usage.Options):
    synopsis = ""

    optParameters = [['path', 'd', FilePath('ca-data'), 'Path to CA.', FilePath],
                     ]
    subCommands = [['init', '', InitOptions, ''],
                   ['sign-request', '', SignRequestOptions, ''],
                   ]
    optFlags = [['verbose', 'v']]

    def postOptions(self):
        if self['verbose']:
            from twisted.python.log import startLogging
            import sys
            startLogging(sys.stdout)
        self.store = CertificateStore.fromFilePath(self['path'])


def main(reactor, *argv):
    config = Options()
    config.parseOptions(argv[1:])
    return maybeDeferred(config.subOptions.run)
