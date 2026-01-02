import rzpipe
import json

class RizinAnalyzer:
    """
    一个用于调用 rzpipe 并提取二进制文件信息的模块。
    """
    def __init__(self, file_path):
        self.file_path = file_path
        self.rz = None

    def open(self):
        """
        初始化 Rizin 管道并打开文件。
        """
        try:
            # 添加 flags=['-2'] 来静默 stderr 输出
            self.rz = rzpipe.open(self.file_path, flags=['-2']) 
            self.rz.cmd("e ghidra.verbose=false")  # 禁用 Ghidra 插件的冗长输出
            return True
        except Exception as e:
            print(f"Error opening binary with  rzpipe: {e}")
            return False

    def analyze(self, level="aaa"):
        """
        执行分析。默认执行 'aaa' (深度分析)。
        """
        if self.rz:
            self.rz.cmd(level)
            return {"status": "done"}
        else:
            return {"status": "error", "message": "Rizin not opened"}

    def get_functions(self):
        """
        获取函数列表 (JSON 格式)。
        """
        return self.rz.cmdj("aflj") if self.rz else []

    def get_strings(self):
        """
        获取二进制文件中的.data段字符串 (JSON 格式)。
        """
        return self.rz.cmdj("izj") if self.rz else []
    
    def get_disassembly_code(self, address_or_name):
        """
        获取指定地址或函数名的反汇编代码。
        """
        if not self.rz:
            return None
        return self.rz.cmdj(f"pdfj @ {address_or_name}")
    
    def get_decompiled_code(self, address_or_name):
        """
        获取指定地址或函数名的反编译代码 (需要安装 rz-ghidra 插件)。
        """
        if not self.rz:
            return None
        # pdgj 是 rizin-ghidra 提供的反编译命令
        return self.rz.cmdj(f"pdgj @ {address_or_name}")

    def get_info(self):
        """
        获取二进制文件的基本信息。
        """
        return self.rz.cmdj("ij") if self.rz else {}
    
    def get_global_call_graph(self):
        """
        获取全局调用图 (JSON 格式)。
        """
        return self.rz.cmdj("agC json") if self.rz else {}

    def close(self):
        """
        关闭 Rizin 实例并释放资源。
        """
        if self.rz:
            self.rz.quit()
            self.rz = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
