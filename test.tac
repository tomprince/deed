from twisted.application import service
application = service.Application('ca-tool-daemon')
from deed.wiring import AMPService
from deed.authority import CertificateStore, CertificateStoreServer

from twisted.python.filepath import FilePath
store = CertificateStore.fromFilePath(FilePath('.ca-data'))
AMPService('unix:test.sock', CertificateStoreServer(store)).setServiceParent(application)

