# O-MVLL 混淆配置,由 obfuscate_build.sh 通过 OMVLL_CONFIG 传入
# 注意: 不启用字符串加密 pass(StringEncOptGlobal) —— 其生成的
# "指针->CString 重定向"结构会让 Xcode 26 的 ld 与 ld_classic 都崩溃
# (assertion: contentType == typeCString)。同时不启用函数抽取/基本块复制:
# 两者会把 ARC block 辅助符号(___destroy_helper_block_*)提升为强符号,
# 造成跨编译单元 duplicate symbol 链接错误。
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

    # 间接调用
    def indirect_call(self, mod: omvll.Module, func: omvll.Function):
        return omvll.ObfuscationConfig.default_config(self, mod, func, [], [], [], 10)

    # 控制流分裂(bogus control flow 等价物)
    def break_control_flow(self, mod: omvll.Module, func: omvll.Function):
        return omvll.ObfuscationConfig.default_config(self, mod, func, [], [], [], 10)

@lru_cache(maxsize=1)
def omvll_get_config() -> omvll.ObfuscationConfig:
    return GuardConfig()
