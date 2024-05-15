from fastapi import FastAPI
import uvicorn
from src.api import ProcessFile,DeleteFile,SignalFileProcessed,RetrieveProcessedFileData,IssueToken
app = FastAPI()
app.include_router(IssueToken.app)
app.include_router(RetrieveProcessedFileData.app)
app.include_router(SignalFileProcessed.app)
app.include_router(DeleteFile.app)
app.include_router(ProcessFile.app)
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)