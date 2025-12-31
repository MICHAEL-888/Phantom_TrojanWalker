import os, shutil, uuid
from fastapi import FastAPI, UploadFile, File, HTTPException
from rz_pipe.analyzer import RizinAnalyzer

app = FastAPI()
analyzer = None
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    global analyzer
    path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4()}_{file.filename}")
    with open(path, "wb") as f: shutil.copyfileobj(file.file, f)
    if analyzer: analyzer.close()
    analyzer = RizinAnalyzer(path)
    if not analyzer.open(): raise HTTPException(500, "Rizin open failed")
    return {"status": "ok"}

@app.get("/analyze")
def do_analyze(level: str = "aaa"):
    analyzer.analyze(level)
    return {"status": "done"}

@app.get("/metadata")
def get_meta(): return analyzer.get_info()

@app.get("/functions")
def get_funcs(): return analyzer.get_functions()

@app.get("/strings")
def get_strs(): return analyzer.get_strings()

@app.get("/decompile")
def decompile(addr: str):
    code = analyzer.get_decompiled_code(addr)
    if not code: raise HTTPException(404, "Not found")
    return {"code": code}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
