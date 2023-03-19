"""
app运行正常 frida so层hook bug
模拟器运行so函数bug
"""
import logging
import posixpath
import sys

from unicorn import UcError, UC_HOOK_MEM_UNMAPPED, UC_HOOK_CODE
from unicorn.arm_const import *
from unicorn.unicorn_const import UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ

from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def

import debug_utils


# Create java class.
class MainActivity(metaclass=JavaClassDef, jvm_name='com/example/jnindk02/MainActivity'):

    def __init__(self):
        pass

    @java_method_def(name='add', signature='(FF)F', native=True)
    def add(self, uc):
        pass

    @java_method_def(name='sub', signature='(FF)F', native=True)
    def sub(self, uc):
        pass

    @java_method_def(name='mul', signature='(FF)F', native=True)
    def mul(self, uc):
        pass

    @java_method_def(name='div', signature='(FF)F', native=True)
    def div(self, uc):
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
emulator.java_classloader.add_class(MainActivity)

# Load all libraries.
emulator.load_library("example_binaries/32/liblog.so")
emulator.load_library("example_binaries/32/libm.so")
emulator.load_library("example_binaries/32/libdl.so")
emulator.load_library("example_binaries/32/libc.so")
lib_module = emulator.load_library("example_binaries/32/libnative-lib_jnindk02.so")

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
    emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x0)

    # Do native stuff.
    a, b = 200, 100
    main_activity = MainActivity()
    main_activity.add(emulator, a, b)
    logger.info(emulator.uc.reg_read(UC_ARM_REG_R0))

    main_activity.sub(emulator, a, b)
    logger.info(emulator.uc.reg_read(UC_ARM_REG_R0))

    main_activity.mul(emulator, a, b)
    logger.info(emulator.uc.reg_read(UC_ARM_REG_R0))

    main_activity.div(emulator, a, b)
    logger.info(emulator.uc.reg_read(UC_ARM_REG_R0))

    # Dump natives found.
    logger.info("Exited EMU.")
    logger.info("Native methods registered to MainActivity:")

    for method in MainActivity.jvm_methods.values():
        if method.native:
            logger.info("- [0x%08x] %s - %s" % (method.native_addr, method.name, method.signature))
except UcError as e:
    print("Exit at %x" % emulator.uc.reg_read(UC_ARM_REG_PC))
    raise
