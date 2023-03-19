"""
@Time : 2023/3/19 9:41 
@Author : Tesla
@File : Crackme01.py 
@Software: PyCharm
@Csdn : https://blog.csdn.net/zhu6201976

动态注册 并且需要传递Context参数
"""
import logging
import sys

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *

from androidemu.emulator import Emulator
from androidemu.java.helpers.native_method import native_method
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def

import debug_utils


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
emulator = Emulator(vfp_inst_set=True)

# Register Java class.
# emulator.java_classloader.add_class(MainActivity)
emulator.java_classloader.add_class(android_content_Context)

emulator.load_library("example_binaries/32/libc.so", do_init=False)
lib_module = emulator.load_library("example_binaries/32/libwolf.so", do_init=False)

# Show loaded modules.
logger.info("Loaded modules:")
for module in emulator.modules:
    logger.info("[0x%x] %s" % (module.base, module.filename))


# Add debugging.
def hook_code(uc, address, size, user_data):
    instruction = uc.mem_read(address, size)
    instruction_str = ''.join('{:02x} '.format(x) for x in instruction)
    print('# Tracing instruction at 0x%x, instruction size = 0x%x, instruction = %s' % (address, size, instruction_str))


emulator.uc.hook_add(UC_HOOK_CODE, hook_code)

# 模拟运行获取静态密码wojiushidaan 并未生成动态密码 aiyou,bucuoo
emulator.call_symbol(lib_module,
                     'Java_com_yaotong_crackme_MainActivity_securityCheck',
                     emulator.java_vm.jni_env.address_ptr,
                     0x0,
                     'wojiushidaan')

for R in [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6,
          UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12, UC_ARM_REG_PC]:
    print("%s" % emulator.uc.reg_read(R))  # 1 success 0 fail
