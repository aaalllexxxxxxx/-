# O-MVLL 混淆配置,由 obfuscate_build.sh 通过 OMVLL_CONFIG 传入
# pass 强度参考官方 sample,概率类 pass 保持在较低值以控制体积与编译时间
import omvll
from functools import lru_cache


class GuardConfig(omvll.ObfuscationConfig):
    def __init__(self):
        super().__init__()

    # 算术表达式混淆
    def obfuscate_arithmetic(self, mod: omvll.Module,
                             fun: omvll.Function) -> omvll.ArithmeticOpt:
        return True

    # 控制流平坦化
    def flatten_cfg(self, mod: omvll.Module, func: omvll.Function):
        return True

    # 字符串加密(1.9.1 起支持 ObjC CFString)
    def obfuscate_string(self, _, __, string: bytes):
        return omvll.StringEncOptGlobal()

    # 间接调用
    def indirect_call(self, mod: omvll.Module, func: omvll.Function):
        return omvll.ObfuscationConfig.default_config(self, mod, func, [], [], [], 10)

    # 控制流分裂(bogus control flow 等价物)
    def break_control_flow(self, mod: omvll.Module, func: omvll.Function):
        return omvll.ObfuscationConfig.default_config(self, mod, func, [], [], [], 10)

    # 函数抽取 / 基本块复制,低概率控制体积
    def function_outline(self, _, __):
        return omvll.FunctionOutlineWithProbability(10)

    def basic_block_duplicate(self, _, __):
        return omvll.BasicBlockDuplicateWithProbability(10)


@lru_cache(maxsize=1)
def omvll_get_config() -> omvll.ObfuscationConfig:
    return GuardConfig()
