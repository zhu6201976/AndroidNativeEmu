"""
模拟成功

动态注册
"""
import logging
import posixpath
import sys

from unicorn import UcError, UC_HOOK_MEM_UNMAPPED, UC_HOOK_CODE
from unicorn.arm_const import *

from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def

import debug_utils


# Create java class.
class NetCrypto(metaclass=JavaClassDef, jvm_name='com/izuiyou/network/NetCrypto'):

    def __init__(self):
        pass

    @java_method_def(name='getProtocolKey', signature='()Ljava/lang/String;', native=True)
    def getProtocolKey(self, uc):
        pass

    @java_method_def(name='setProtocolKey', signature='(Ljava/lang/String;)V', native=True)
    def setProtocolKey(self, uc):
        pass

    @java_method_def(name='native_init', signature='()V', native=True)
    def native_init(self, uc):
        pass

    @java_method_def(name='encodeAES', signature='([B)[B', native=True)
    def encodeAES(self, uc):
        pass

    @java_method_def(name='decodeAES', signature='([BZ)[B', native=True)
    def decodeAES(self, uc):
        pass

    @java_method_def(name='generateSign', signature='([B)Ljava/lang/String;', native=True)
    def generateSign(self, uc):
        pass

    @java_method_def(name='registerDID', signature='([B)Z', native=True)
    def registerDID(self, uc):
        pass

    @java_method_def(name='sign', signature='(Ljava/lang/String;[B)Ljava/lang/String;', native=True)
    def sign(self, uc):
        pass


# Configure logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize emulator
emulator = Emulator(
    vfp_inst_set=True,
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
)

# emulator.uc.hook_add(UC_HOOK_CODE, debug_utils.hook_code)
# emulator.uc.hook_add(UC_HOOK_MEM_UNMAPPED, debug_utils.hook_unmapped)

# Register Java class.
emulator.java_classloader.add_class(NetCrypto)

# Load all libraries.
emulator.load_library("example_binaries/32/libc.so")
# emulator.load_library("example_binaries/32/libdl.so")
# emulator.load_library("example_binaries/32/libstdc++.so")
# emulator.load_library("example_binaries/32/libm.so")
# emulator.load_library("example_binaries/32/liblog.so")
lib_module = emulator.load_library("example_binaries/32/libnet_crypto.so")

# Show loaded modules.
logger.info("Loaded modules:")
for module in emulator.modules:
    logger.info("=> 0x%08x - %s" % (module.base, module.filename))

# Debug
emulator.uc.hook_add(UC_HOOK_CODE, debug_utils.hook_code)
# emulator.uc.hook_add(UC_HOOK_MEM_UNMAPPED, debug_utils.hook_unmapped)
# emulator.uc.hook_add(UC_HOOK_MEM_WRITE, debug_utils.hook_mem_write)
# emulator.uc.hook_add(UC_HOOK_MEM_READ, debug_utils.hook_mem_read)

try:
    # Run JNI_OnLoad.
    #   JNI_OnLoad will call 'RegisterNatives'.
    emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)

    # Do native stuff.
    main_activity = NetCrypto()
    # main_activity.native_init(emulator)
    # logger.info("Response from JNI call: %s" % main_activity.setProtocolKey(emulator, 'duck-1680937792-QApRr6VD8djK7RtHZC/17wG5mE3ZSdk0i2VWQ20uo67h8uf8b1MvbbZKEFGf4fLTjybZRFh557+V6tLyC0R86TCp/XATGr3QbdUXazV5JeU='))
    logger.info("Response from JNI call: %s" % main_activity.getProtocolKey(emulator))
    # logger.info("Response from JNI call: %s" % main_activity.encodeAES(emulator, bytearray([1,2,3,4,5])))
    logger.info(emulator.uc.reg_read(UC_ARM_REG_R0))  # 1 success 0 fail

    # Dump natives found.
    logger.info("Exited EMU.")
    logger.info("Native methods registered to NetCrypto:")

    for method in NetCrypto.jvm_methods.values():
        if method.native:
            logger.info("- [0x%08x] %s - %s" % (method.native_addr, method.name, method.signature))
except UcError as e:
    print("Exit at %x" % emulator.uc.reg_read(UC_ARM_REG_PC))
    raise
