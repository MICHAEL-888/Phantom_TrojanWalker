import logging
from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import JSONResponse
from colorama import Fore, Style, init
from dotenv import load_dotenv

from config_loader import load_config
from agent_core import FunctionAnalysisAgent, MalwareAnalysisAgent
from rizin_client import RizinClient
from analysis_coordinator import AnalysisCoordinator
from exceptions import TrojanWalkerError

load_dotenv()
init(autoreset=True)

# 自定义彩色日志格式
class ColoredFormatter(logging.Formatter):
    def format(self, record):
        level_colors = {
            logging.DEBUG: Fore.BLUE,
            logging.INFO: Fore.CYAN,
            logging.WARNING: Fore.YELLOW,
            logging.ERROR: Fore.RED,
            logging.CRITICAL: Fore.RED + Style.BRIGHT,
        }
        color = level_colors.get(record.levelno, Fore.WHITE)
        
        # 组装彩色字符串
        asctime = f"{Fore.GREEN}{self.formatTime(record, '%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}"
        level = f"{color}{record.levelname:<8}{Style.RESET_ALL}"
        msg = f"{Style.BRIGHT}{record.msg}{Style.RESET_ALL}" if record.levelno == logging.INFO else record.msg
        
        return f"{asctime} - {level} - {msg}"

# 配置日志
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter())
# 配置根日志或特定模块日志
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
# 避免重复 handler
if not any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers):
    root_logger.addHandler(handler)

# 屏蔽第三方库的冗余日志 (如 httpx 和 httpcore)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# 也是为了确保 agent 模块的日志能打出来
logger = logging.getLogger(__name__)

app = FastAPI()

# 全局异常处理: 捕获自定义异常
@app.exception_handler(TrojanWalkerError)
async def trojan_walker_exception_handler(request: Request, exc: TrojanWalkerError):
    logger.error(f"Known Application Error: {str(exc)}")
    return JSONResponse(
        status_code=500, # 或者根据异常类型返回不同状态码
        content={"status": "error", "type": type(exc).__name__, "message": str(exc)},
    )

# 全局异常处理: 捕获未知异常
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled Exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"status": "error", "type": "InternalServerError", "message": "An unexpected error occurred."},
    )

# 初始化服务组件
try:
    logger.info("Initializing services...")
    config = load_config()
    
    # 实例化 Rizin 客户端
    rizin_client = RizinClient(config)
    
    # 实例化 Agents
    function_agent = FunctionAnalysisAgent()
    malware_agent = MalwareAnalysisAgent()
    
    # 实例化协调器
    coordinator = AnalysisCoordinator(rizin_client, function_agent, malware_agent)
    logger.info("Services initialized successfully.")
except Exception as e:
    logger.critical(f"Failed to initialize services: {e}")
    # 这里我们不用 raise e 终止程序，因为 uvicorn 会继续运行，但在请求时可能会报错
    coordinator = None

@app.post("/analyze")
async def analyze_endpoint(file: UploadFile = File(...)):
    """
    接收一个文件，并协调 Rizin 后端进行分析，提取元数据、函数、字符串、调用图和反编译代码。
    """
    if coordinator is None:
        raise TrojanWalkerError("Service not initialized properly.")
        
    return await coordinator.analyze_file(file)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)

