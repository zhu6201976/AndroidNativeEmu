"""
32位模拟成功 64位失败
"""

import logging
import sys

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *
import posixpath

from androidemu.emulator import Emulator

# Configure logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize emulator
emulator = Emulator(vfp_inst_set=True,
                    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
                    )
emulator.load_library("example_binaries/32/libc.so", do_init=False)
emulator.load_library("example_binaries/32/libm.so", do_init=False)
lib_module = emulator.load_library("example_binaries/32/libcyberpeace.so", do_init=False)

# Show loaded modules.
logger.info("Loaded modules:")
for module in emulator.modules:
    logger.info("[0x%x] %s" % (module.base, module.filename))


# Add debugging.
def hook_code(uc, address, size, user_data):
    instruction = uc.mem_read(address, size)
    instruction_str = ''.join('{:02x} '.format(x) for x in instruction)
    print('# Tracing instruction at 0x%x, instruction size = 0x%x, instruction = %s' % (address, size, instruction_str))


# emulator.uc.hook_add(UC_HOOK_CODE, hook_code)

emulator.call_symbol(lib_module,
                     'Java_com_testjava_jack_pingan2_cyberpeace_CheckString',
                     emulator.java_vm.jni_env.address_ptr,
                     0x0,
                     '1234567890')  # 90705bb55efb59da7fc2a5636549812a 1234567890

print("%s" % emulator.uc.reg_read(UC_ARM_REG_R0))
