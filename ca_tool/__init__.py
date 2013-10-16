
def patchSSL():
    from twisted.internet.ssl import (
        KeyPair, CertificateRequest)

    from OpenSSL import crypto
    @classmethod
    def loadPEM(cls, data):
        return cls.load(data, crypto.FILETYPE_PEM)
    def dumpPEM(self):
        return self.dump(crypto.FILETYPE_PEM)
    KeyPair.loadPEM = CertificateRequest.loadPEM = loadPEM
    KeyPair.dumpPEM = CertificateRequest.dumpPEM = dumpPEM

patchSSL()
del patchSSL
