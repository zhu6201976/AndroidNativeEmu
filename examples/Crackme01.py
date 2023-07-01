"""
@Time : 2023/3/19 9:41 
@Author : Tesla
@File : Crackme01.py 
@Software: PyCharm
@Csdn : https://blog.csdn.net/zhu6201976

动态注册 需传递Context参数
com.wolf.ndktest.MainActivity
so wolf
public static native void greywolf(Context context, String str);

加载运行so失败
2023-03-19 21:42:54,802   DEBUG                androidemu.emulator | Calling init for: example_binaries/32/libwolf.so
2023-03-19 21:42:54,802   DEBUG                androidemu.emulator | Calling Init function: a00b1c4d
2023-03-19 21:42:54,805   DEBUG                androidemu.emulator | Calling Init function: a00b1c88
2023-03-19 21:42:54,808   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall mmap2(00000000, 00001000, 00000003, 00000022, ffffffff, 00000000) at 0xa0049bc4
2023-03-19 21:42:54,808   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall madvise(e0200000, 00001000, 0000000c) at 0xa004a78c
2023-03-19 21:42:54,808   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall prctl(53564d41, 00000000, e0200000, 00001000, a0053db4) at 0xa004a97c
2023-03-19 21:42:54,808   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall mprotect(e0200000, 00001000, 00000001) at 0xa004a874
2023-03-19 21:42:54,811   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall mprotect(e0200000, 00001000, 00000003) at 0xa004a874
2023-03-19 21:42:54,811   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall mprotect(e0200000, 00001000, 00000001) at 0xa004a874
2023-03-19 21:42:54,811   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall mprotect(e0200000, 00001000, 00000003) at 0xa004a874
2023-03-19 21:42:54,811   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall mprotect(e0200000, 00001000, 00000001) at 0xa004a874
2023-03-19 21:42:54,811   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall mprotect(e0200000, 00001000, 00000003) at 0xa004a874
2023-03-19 21:42:54,811   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall mprotect(e0200000, 00001000, 00000001) at 0xa004a874

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


class MainActivity(metaclass=JavaClassDef, jvm_name='com/wolf/ndktest/MainActivity'):
    def __init__(self):
        pass

    @java_method_def(name='greywolf', signature='(android/content/Context;Ljava/lang/String;)V', native=True)
    def greywolf(self, uc):
        pass


class android_content_Context(metaclass=JavaClassDef, jvm_name='android/content/Context'):
    def __init__(self):
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
emulator.java_classloader.add_class(android_content_Context)

# Load all libraries.
emulator.load_library("example_binaries/32/libc.so")
# emulator.load_library("example_binaries/32/libdl.so")
# emulator.load_library("example_binaries/32/libstdc++.so")
# emulator.load_library("example_binaries/32/libm.so")
# emulator.load_library("example_binaries/32/liblog.so")
lib_module = emulator.load_library("example_binaries/32/libwolf.so")

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
    main_activity = MainActivity()
    context = android_content_Context()
    logger.info("Response from JNI call: %s" % main_activity.greywolf(emulator, context, 'hello5.1'))  # hello5.1

    # Dump natives found.
    logger.info("Exited EMU.")
    logger.info("Native methods registered to MainActivity:")
    for method in MainActivity.jvm_methods.values():
        if method.native:
            logger.info("- [0x%08x] %s - %s" % (method.native_addr, method.name, method.signature))
except UcError as e:
    print("Exit at %x" % emulator.uc.reg_read(UC_ARM_REG_PC))
    raise


