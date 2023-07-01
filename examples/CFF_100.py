"""
模拟成功 动态注册

RuntimeError: Unhandled syscall 0x78 (120) at 0xa001f10c, stopping emulation
这个错误是因为在模拟执行指令的过程中遇到了系统调用 0x78，也就是 gettid()，但是这个系统调用没有被模拟处理。因此模拟引擎抛出了一个异常，并停止了模拟。
解决这个问题的方法是在模拟引擎中添加处理 gettid() 系统调用的函数。你可以参考该框架中已经实现的其他系统调用处理函数，编写一个处理 gettid() 的函数，
然后将其注册到模拟引擎中。这样当模拟引擎执行到 gettid() 系统调用时，就会调用你编写的处理函数，并正常返回。

修改源码成功实现运行!!! 全局搜索 Tesla 为修改的源码 --> 恢复
AndroidNativeEmu\src\androidemu\cpu\syscall_hooks.py
AndroidNativeEmu\src\androidemu\cpu\syscall_handlers.py

运行结果
2023-03-19 21:24:28,586   DEBUG        androidemu.internal.modules | Loading module 'example_binaries/32/libc.so'.
2023-03-19 21:24:28,591   DEBUG        androidemu.internal.modules | => Base address: 0xa0000000
2023-03-19 21:24:28,606   ERROR        androidemu.internal.modules | => Undefined external symbol: android_get_application_target_sdk_version
2023-03-19 21:24:28,606   ERROR        androidemu.internal.modules | => Undefined external symbol: dl_unwind_find_exidx
2023-03-19 21:24:29,092   ERROR        androidemu.internal.modules | => Undefined external symbol: android_get_application_target_sdk_version
2023-03-19 21:24:29,093   ERROR        androidemu.internal.modules | => Undefined external symbol: dl_unwind_find_exidx
2023-03-19 21:24:29,337   DEBUG                androidemu.emulator | Calling init for: example_binaries/32/libc.so
2023-03-19 21:24:29,337   DEBUG                androidemu.emulator | Calling Init function: a0017d05
2023-03-19 21:24:29,337   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall mprotect(a0094000, 00001000, 00000001) at 0xa004a874
2023-03-19 21:24:29,337   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall mprotect(a0094000, 00001000, 00000003) at 0xa004a874
2023-03-19 21:24:29,337   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall faccessat(ffffff9c, a001ac34, 00000004, 00000000) at 0xa0049874
2023-03-19 21:24:29,338   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall getpid() at 0xa0049b14
2023-03-19 21:24:29,338   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall getrandom(100fff78, 00000028, 00000001) at 0xa001910c
2023-03-19 21:24:29,338   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall mmap2(00000000, 00000448, 00000003, 00000022, ffffffff, 00000000) at 0xa0049bc4
2023-03-19 21:24:29,339   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall madvise(e0000000, 00000448, 0000000c) at 0xa004a78c
2023-03-19 21:24:29,339   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall prctl(53564d41, 00000000, e0000000, 00000448, a003d9c8) at 0xa004a97c
2023-03-19 21:24:29,340   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall mprotect(a0094000, 00001000, 00000001) at 0xa004a874
2023-03-19 21:24:29,341   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall openat(ffffff9c, a0071384, 00020000, 00000000) at 0xa0049be4
2023-03-19 21:24:29,341    INFO         androidemu.vfs.file_system | File opened '/proc/sys/vm/overcommit_memory'
2023-03-19 21:24:29,342   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall read(00000003, 100feefb, 00000001) at 0xa004aa7c
2023-03-19 21:24:29,342    INFO         androidemu.vfs.file_system | Reading 1 bytes from '/proc/sys/vm/overcommit_memory'
2023-03-19 21:24:29,342   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall close(00000003) at 0xa0049854
2023-03-19 21:24:29,342    INFO         androidemu.vfs.file_system | File closed '/proc/sys/vm/overcommit_memory'
2023-03-19 21:24:29,344   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall mmap2(00000000, 00080000, 00000003, 00004022, ffffffff, 00000000) at 0xa0049bc4
2023-03-19 21:24:29,344   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall madvise(e0001000, 00080000, 0000000c) at 0xa004a78c
2023-03-19 21:24:29,344   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall prctl(53564d41, 00000000, e0001000, 00080000, a0071068) at 0xa004a97c
2023-03-19 21:24:29,344   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall munmap(e0001000, 00080000) at 0xa004a8f4
2023-03-19 21:24:29,345   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall mmap2(00000000, 000ff000, 00000003, 00004022, ffffffff, 00000000) at 0xa0049bc4
2023-03-19 21:24:29,345   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall madvise(e0081000, 000ff000, 0000000c) at 0xa004a78c
2023-03-19 21:24:29,345   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall prctl(53564d41, 00000000, e0081000, 000ff000, a0071068) at 0xa004a97c
2023-03-19 21:24:29,345   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall munmap(e0081000, 0007f000) at 0xa004a8f4
2023-03-19 21:24:29,347   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall clock_gettime(00000006, 100feeac) at 0xa00499ec
2023-03-19 21:24:29,348   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall openat(ffffff9c, a00221b4, 000a0000, 00000000) at 0xa0049be4
2023-03-19 21:24:29,349    INFO         androidemu.vfs.file_system | File opened '/sys/devices/system/cpu/online'
2023-03-19 21:24:29,350   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall mmap2(00000000, 00080000, 00000003, 00004022, ffffffff, 00000000) at 0xa0049bc4
2023-03-19 21:24:29,350   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall madvise(e0180000, 00080000, 0000000c) at 0xa004a78c
2023-03-19 21:24:29,350   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall prctl(53564d41, 00000000, e0180000, 00080000, a0071068) at 0xa004a97c
2023-03-19 21:24:29,353   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall fstat64(00000004, 100ffea0) at 0xa004a314
2023-03-19 21:24:29,353    INFO         androidemu.vfs.file_system | File stat64 '/sys/devices/system/cpu/online'
2023-03-19 21:24:29,353   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall read(00000004, e0189000, 00000400) at 0xa004aa7c
2023-03-19 21:24:29,354    INFO         androidemu.vfs.file_system | Reading 1024 bytes from '/sys/devices/system/cpu/online'
2023-03-19 21:24:29,354   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall read(00000004, e0189000, 00000400) at 0xa004aa7c
2023-03-19 21:24:29,354    INFO         androidemu.vfs.file_system | Reading 1024 bytes from '/sys/devices/system/cpu/online'
2023-03-19 21:24:29,355   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall close(00000004) at 0xa0049854
2023-03-19 21:24:29,355    INFO         androidemu.vfs.file_system | File closed '/sys/devices/system/cpu/online'
2023-03-19 21:24:29,356   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall fstatat64(ffffff9c, a0091174, 100fff70, 00000000) at 0xa004a334
2023-03-19 21:24:29,356    INFO         androidemu.vfs.file_system | File fstatat64 '/dev/__properties__'
2023-03-19 21:24:29,357 WARNING         androidemu.vfs.file_system | > File was not found.
2023-03-19 21:24:29,357   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall openat(ffffff9c, a0091174, 000a8000, 00000000) at 0xa0049be4
2023-03-19 21:24:29,357 WARNING         androidemu.vfs.file_system | File does not exist '/dev/__properties__'
2023-03-19 21:24:29,357   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall mprotect(a0094000, 00001000, 00000003) at 0xa004a874
2023-03-19 21:24:29,358   DEBUG            androidemu.native.hooks | Called __system_property_get(libc.debug.malloc.options, 0x100ffedc)
2023-03-19 21:24:29,358   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall mprotect(a0094000, 00001000, 00000001) at 0xa004a874
2023-03-19 21:24:29,358   DEBUG            androidemu.native.hooks | Called dlopen(libvendorconn.so)
2023-03-19 21:24:29,358   DEBUG        androidemu.internal.modules | Loading module 'D:\study\Python\Projects\AndroidNativeEmu\src\androidemu\libs\libvendorconn_32.so'.
2023-03-19 21:24:29,360   DEBUG        androidemu.internal.modules | => Base address: 0xa009b000
2023-03-19 21:24:29,365   DEBUG                androidemu.emulator | Calling init for: D:\study\Python\Projects\AndroidNativeEmu\src\androidemu\libs\libvendorconn_32.so
2023-03-19 21:24:29,365   DEBUG            androidemu.native.hooks | Called dlsym(0xa009b000, isVendorExtAvailable)
2023-03-19 21:24:29,366   DEBUG            androidemu.native.hooks | Called dlclose(0xa009b000)
2023-03-19 21:24:29,366   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall futex(a0093030, 00000081, 7fffffff, 00000000, 00000000, 00000000) at 0xa001910c
2023-03-19 21:24:29,366   DEBUG            androidemu.native.hooks | Called dlopen(libnetd_client.so)
2023-03-19 21:24:29,366   DEBUG            androidemu.native.hooks | Called dlsym(0xffffffff, netdClientInitAccept4)
2023-03-19 21:24:29,366   DEBUG            androidemu.native.hooks | Called dlsym(0xffffffff, netdClientInitConnect)
2023-03-19 21:24:29,366   DEBUG            androidemu.native.hooks | Called dlsym(0xffffffff, netdClientInitNetIdForResolv)
2023-03-19 21:24:29,367   DEBUG            androidemu.native.hooks | Called dlsym(0xffffffff, netdClientInitSocket)
2023-03-19 21:24:29,367   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall futex(a009302c, 00000081, 7fffffff, 00000000, 00000000, 00000000) at 0xa001910c
2023-03-19 21:24:29,367   DEBUG                androidemu.emulator | Calling Init function: a003178d
2023-03-19 21:24:29,367   DEBUG                androidemu.emulator | Calling Init function: a006e381
2023-03-19 21:24:29,367   DEBUG        androidemu.internal.modules | Loading module 'example_binaries/32/libctf.so'.
2023-03-19 21:24:29,369   DEBUG        androidemu.internal.modules | => Base address: 0xa009e000
2023-03-19 21:24:29,379   DEBUG                androidemu.emulator | Calling init for: example_binaries/32/libctf.so
2023-03-19 21:24:29,379   DEBUG                androidemu.emulator | Calling Init function: a009f07d
2023-03-19 21:24:29,380   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall gettid() at 0xa001910c
2023-03-19 21:24:29,380   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall prctl(59616d61, 00002211, 00000000, ffffffff, 00000000) at 0xa004a97c
2023-03-19 21:24:29,381   DEBUG    androidemu.cpu.syscall_handlers | Executing syscall prctl(00000004, 00000001, 00000000, ffffffff, 00000000) at 0xa004a97c
2023-03-19 21:24:29,381    INFO                           __main__ | Loaded modules:
2023-03-19 21:24:29,381    INFO                           __main__ | => 0xa0000000 - example_binaries/32/libc.so
2023-03-19 21:24:29,381    INFO                           __main__ | => 0xa009b000 - D:\study\Python\Projects\AndroidNativeEmu\src\androidemu\libs\libvendorconn_32.so
2023-03-19 21:24:29,381    INFO                           __main__ | => 0xa009e000 - example_binaries/32/libctf.so
2023-03-19 21:24:29,381   DEBUG            androidemu.java.java_vm | java_vm: 0x20000056
2023-03-19 21:24:29,381   DEBUG            androidemu.java.java_vm | env: 0x100fffe8
2023-03-19 21:24:29,381   DEBUG            androidemu.java.java_vm | version: 0x00010004
2023-03-19 21:24:29,381   DEBUG            androidemu.java.java_vm | JavaVM->GetENV() was called!
2023-03-19 21:24:29,381   DEBUG            androidemu.java.jni_env | JNIEnv->FindClass(com/ctf/test/ctf_100/MainActivity) was called
2023-03-19 21:24:29,382   DEBUG            androidemu.java.jni_env | JNIEnv->RegisterNatives(1, 0x100fffec, 1) was called
2023-03-19 21:24:29,382   DEBUG     androidemu.java.java_class_def | Registered native function ('get_flag', '(I)Ljava/lang/String;') to MainActivity.get_flag
2023-03-19 21:24:29,382   DEBUG            androidemu.java.jni_env | JNIEnv->NewStringUtf(268796A5E68A25A1) was called
2023-03-19 21:24:29,382    INFO                           __main__ | Response from JNI call: 268796A5E68A25A1
2023-03-19 21:24:29,383    INFO                           __main__ | Exited EMU.
2023-03-19 21:24:29,383    INFO                           __main__ | Native methods registered to MainActivity:
2023-03-19 21:24:29,383    INFO                           __main__ | - [0xa009ef91] get_flag - (I)Ljava/lang/String;
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
class MainActivity(metaclass=JavaClassDef, jvm_name='com/ctf/test/ctf_100/MainActivity'):

    def __init__(self):
        pass

    @java_method_def(name='get_flag', signature='(I)Ljava/lang/String;', native=True)
    def get_flag(self, uc):
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
emulator.load_library("example_binaries/32/libc.so")
# emulator.load_library("example_binaries/32/libdl.so")
# emulator.load_library("example_binaries/32/libstdc++.so")
# emulator.load_library("example_binaries/32/libm.so")
# emulator.load_library("example_binaries/32/liblog.so")
lib_module = emulator.load_library("example_binaries/32/libctf.so")

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
    main_activity = MainActivity()
    logger.info("Response from JNI call: %s" % main_activity.get_flag(emulator, 32000))

    # Dump natives found.
    logger.info("Exited EMU.")
    logger.info("Native methods registered to MainActivity:")

    for method in MainActivity.jvm_methods.values():
        if method.native:
            logger.info("- [0x%08x] %s - %s" % (method.native_addr, method.name, method.signature))
except UcError as e:
    print("Exit at %x" % emulator.uc.reg_read(UC_ARM_REG_PC))
    raise
