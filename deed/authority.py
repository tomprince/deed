# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Certificate Stores
"""

from hashlib import md5
import struct

from zope.interface import implementer

from twisted.python import log
from twisted.internet import defer

from twisted.internet.ssl import (
    Certificate, KeyPair, CertificateRequest, PrivateCertificate,
    DistinguishedName)

from deed.interfaces import (
        CertificateNotFound,
    ICertificateStore)



class BadCertificateRequest(Exception):
    pass



def signCertificateRequest(certificateRequest, authority, serial):
    newCert = authority.signRequestObject(
            certificateRequest,
            serial,
            digestAlgorithm='sha512')
    log.msg(format='signing certificate for %(name)s: %(digest)s',
            name=certificateRequest.getSubject(), digest=newCert.digest())
    return newCert

def genSerial(name):
    return abs(struct.unpack('!i', md5(name).digest()[:4])[0])


def generateKey():
    return KeyPair.generate()

def generateCertificateRequest(key, subjectName):
    dn = DistinguishedName(commonName=subjectName)
    return key.requestObject(dn)

def generateSelfSignedCertificate(key, subjectName):
    dn = DistinguishedName(commonName=subjectName)
    req = key.requestObject(dn)
    cert = key.signRequestObject(dn, req, genSerial(subjectName), digestAlgorithm='sha512')
    return cert





@implementer(ICertificateStore)
class CertificateStore(object):

    @classmethod
    def fromFilePath(cls, filePath):
        privatePath = filePath.child('private')
        publicPath = filePath.child('public')
        csrPath = filePath.child('csr')

        issuerPath = filePath.child('issuer')
        if issuerPath.exists():
            issuer = issuerPath.getContent()
            key = KeyPair.loadPEM(privatePath.child(issuer).getContent())
            cert = Certificate.loadPEM(publicPath.child(issuer).getContent())

        store = cls(publicPath, privatePath, csrPath, key, cert, issuer)
        return store

    @classmethod
    def newStore(cls, filePath, issuer):
        if not filePath.exists():
            filePath.createDirectory()

        privatePath = filePath.child('private')
        if not privatePath.exists():
            privatePath.createDirectory()
            privatePath.chmod(0700)

        publicPath = filePath.child('public')
        if not publicPath.exists():
            publicPath.createDirectory()

        csrPath = filePath.child('csr')
        if not csrPath.exists():
            csrPath.createDirectory()

        issuerPath = filePath.child('issuer')
        keyPath = privatePath.child(issuer)
        certPath = publicPath.child(issuer)
        if True: #not issuerPath.exists():
            issuerPath.setContent(issuer)
            issuerPath.chmod(0644)
            key = generateKey()
            keyPath.setContent(key.dumpPEM())
            cert = generateSelfSignedCertificate(key, issuer)
            keyPath.chmod(0600)
            certPath.setContent(cert.dumpPEM())
        else:
            raise Exception

        store = cls(publicPath, privatePath, csrPath, key, cert, issuer)
        return store


    def __init__(self, publicPath, privatePath, csrPath, key, cert, issuer):
        self.publicPath = publicPath
        self.privatePath = privatePath
        self.csrPath = csrPath
        self.cert = PrivateCertificate.fromCertificateAndKeyPair(cert, key)
        self.issuer = issuer

    def submitCertificateRequest(self, certificateRequest):
        log.msg(format='Received certificate request for %(name)s',
                name=certificateRequest.getSubject())
        subject = certificateRequest.getSubject().commonName
        reqPath = self.csrPath.child(subject)
        reqPath.setContent(certificateRequest.dumpPEM())
        reqPath.chmod(0644)
        return defer.succeed(None)

    def getCertificate(self, subject):
        log.msg(format='Retreving certificate for %(name)s',
                name=subject)
        certPath = self.publicPath.child(subject)
        if not certPath.exists():
            raise CertificateNotFound
        cert = Certificate.loadPEM(certPath.getContent())
        return defer.succeed(cert)


    def signRequest(self, subject):
        log.msg(format='Signing certificate for %(name)s',
                name=subject)
        reqPath = self.csrPath.child(subject)
        if not reqPath.exists():
            raise Exception
        req = CertificateRequest.loadPEM(reqPath.getContent())
        cert = self.cert.signRequestObject(req, genSerial(subject), digestAlgorithm='sha512')
        certPath = self.publicPath.child(subject)
        certPath.setContent(cert.dumpPEM())
        certPath.chmod(0644)
        return cert


from zope.interface import implementer
from twisted.internet.endpoints import connectProtocol
from twisted.protocols.amp import AMP
from deed.interfaces import (
    ICertificateStore, GetCertificate, SubmitCertificateRequest)

@implementer(ICertificateStore)
class RemoteCertificateStore(object):

    def __init__(self, proto):
        self._proto = proto

    @classmethod
    def fromEndpoint(cls, endpoint):
        return connectProtocol(endpoint, AMP()).addCallback(cls)

    def getCertificate(self, subject):
        return (self._proto.callRemote(GetCertificate, subject=subject)
                .addCallback(lambda r: r['certificate'])
                .addCallback(Certificate.loadPEM))

    def submitCertificateRequest(self, req):
        return self._proto.callRemote(SubmitCertificateRequest, request=req.dumpPEM())

from twisted.protocols.amp import CommandLocator
class CertificateStoreServer(CommandLocator):

    def __init__(self, store):
        self.store = store

    @GetCertificate.responder
    def getCertificate(self, subject):
        return (self.store.getCertificate(subject)
                .addCallback(lambda cert: {'certificate': cert.dumpPEM()}))

    @SubmitCertificateRequest.responder
    def submitCertificateRequest(self, request):
        request = CertificateRequest.loadPEM(request)
        return (self.store.submitCertificateRequest(request)
                .addCallback(lambda _: {}))


__all__ = [
        'CertificateStore',
        'RemoteCertificateStore'
        ]
