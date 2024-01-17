import logging
import time
from typing import Optional

from bpylist2 import archiver
from packaging.version import Version

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.dvt_testmanaged_proxy import DvtTestmanagedProxyService
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
from pymobiledevice3.services.remote_server import (NSURL, NSUUID, Channel, MessageAux, XCTestConfiguration)

logger = logging.getLogger(__name__)


class AuthorizePidService:
    IDENTIFIER = 'dtxproxy:XCTestManager_IDEInterface:XCTestManager_DaemonConnectionInterface'
    XCODE_VERSION = 36 # not important

    def __init__(self,
                 service_provider: LockdownServiceProvider,
                 pid: int):
        self.service_provider = service_provider
        self.pid = pid
        self.pctl = self.init_process_control()
        self.product_major_version = Version(service_provider.product_version).major

    def run(self):
        # Call authorize
        session_identifier = NSUUID.uuid4()
        
        self.init_ide_channels()
    
        time.sleep(1)
        self.authorize_test_process_id(self._chan1, self.pid)

    def init_process_control(self):
        self._dvt3 = DvtSecureSocketProxyService(lockdown=self.service_provider)
        self._dvt3.perform_handshake()
        return ProcessControl(self._dvt3)
    
    def init_ide_channels(self):
        # XcodeIDE require two connections
        self._dvt1 = DvtTestmanagedProxyService(lockdown=self.service_provider)
        self._dvt1.perform_handshake()

        logger.info('make channel %s', self.IDENTIFIER)
        self._chan1 = self._dvt1.make_channel(self.IDENTIFIER)
        if self.product_major_version >= 11:
            self._dvt1.send_message(
                self._chan1,
                '_IDE_initiateControlSessionWithProtocolVersion:',
                MessageAux().append_obj(self.XCODE_VERSION))
            reply = self._chan1.receive_plist()
            logger.info('conn1 handshake xcode version: %s', reply)

    def authorize_test_process_id(self, chan: Channel, pid: int):
        selector = None
        aux = MessageAux()
        if self.product_major_version >= 12:
            selector = '_IDE_authorizeTestSessionWithProcessID:'
            aux.append_obj(pid)
        elif self.product_major_version >= 10:
            selector = '_IDE_initiateControlSessionForTestProcessID:protocolVersion:'
            aux.append_obj(pid)
            aux.append_obj(self.XCODE_VERSION)
        else:
            selector = '_IDE_initiateControlSessionForTestProcessID:'
            aux.append_obj(pid)
        chan.send_message(selector, aux)
        reply = chan.receive_plist()
        if not isinstance(reply, bool) or reply != True:
            raise RuntimeError('Failed to authorize test process id: %s' % reply)
        logger.info('authorizing test session for pid %d successful %r', pid, reply)
    
    def close(self):
        self._dvt1.close()
        self._dvt3.close()