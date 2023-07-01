"""
@Time : 2023/3/19 8:32 
@Author : Tesla
@File : AliCrackme.py.py 
@Software: PyCharm
@Csdn : https://blog.csdn.net/zhu6201976

模拟运行获取静态密码wojiushidaan 并未生成动态密码aiyou,bucuoo
"""
import logging
import sys

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *

from androidemu.emulator import Emulator

# Configure logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize emulator
emulator = Emulator(vfp_inst_set=True)
emulator.load_library("example_binaries/32/libc.so", do_init=False)
lib_module = emulator.load_library("example_binaries/32/libcrackme.so", do_init=False)

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

# 模拟运行获取静态密码wojiushidaan 并未生成动态密码aiyou,bucuoo
emulator.call_symbol(lib_module,
                     'Java_com_yaotong_crackme_MainActivity_securityCheck',
                     emulator.java_vm.jni_env.address_ptr,
                     0x0,
                     'wojiushidaan')  # aiyou,bucuoo wojiushidaan

logger.info(emulator.uc.reg_read(UC_ARM_REG_R0))  # 1 success 0 fail
