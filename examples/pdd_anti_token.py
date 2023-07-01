"""
模拟失败 动态注册
拼多多 android v5.10.0 anti_token
"""
import logging
import posixpath
import sys
import time

from unicorn import UcError, UC_HOOK_MEM_UNMAPPED, UC_HOOK_CODE
from unicorn.arm_const import *

from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def

import debug_utils


# Create java class.
class DeviceNative(metaclass=JavaClassDef, jvm_name='com/xunmeng/pinduoduo/secure/DeviceNative'):

    def __init__(self):
        pass

    @java_method_def(name='info', signature='(android.content.Context;J)Ljava/lang/String;', native=True)
    def info(self, uc):
        pass

    @java_method_def(name='info2', signature='(android.content.Context;J)Ljava/lang/String;', native=True)
    def info2(self, uc):
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
emulator.java_classloader.add_class(DeviceNative)

# Load all libraries.
emulator.load_library("example_binaries/32/libc.so")
emulator.load_library("example_binaries/32/libdl.so")
emulator.load_library("example_binaries/32/libstdc++.so")
emulator.load_library("example_binaries/32/libm.so")
emulator.load_library("example_binaries/32/liblog.so")
emulator.load_library("example_binaries/32/libUserEnv.so")
lib_module = emulator.load_library("example_binaries/32/libPddSecure.so")

# Show loaded modules.
logger.info("Loaded modules:")
for module in emulator.modules:
    logger.info("=> 0x%08x - %s" % (module.base, module.filename))

# Debug
# emulator.uc.hook_add(UC_HOOK_CODE, debug_utils.hook_code)
# emulator.uc.hook_add(UC_HOOK_MEM_UNMAPPED, debug_utils.hook_unmapped)
# emulator.uc.hook_add(UC_HOOK_MEM_WRITE, debug_utils.hook_mem_write)
# emulator.uc.hook_add(UC_HOOK_MEM_READ, debug_utils.hook_mem_read)

try:
    # Run JNI_OnLoad.
    #   JNI_OnLoad will call 'RegisterNatives'.
    emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)

    # Do native stuff.
    main_activity = DeviceNative()
    logger.info("Response from JNI call: %s" % main_activity.info2(emulator, 1688005725349))

    # Dump natives found.
    logger.info("Exited EMU.")
    logger.info("Native methods registered to MainActivity:")

    for method in DeviceNative.jvm_methods.values():
        if method.native:
            logger.info("- [0x%08x] %s - %s" % (method.native_addr, method.name, method.signature))
except UcError as e:
    print("Exit at %x" % emulator.uc.reg_read(UC_ARM_REG_PC))
    raise
