from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import settings
from health import router as health_router

app = FastAPI(
    title=settings.app_name,
    debug=settings.debug
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router, tags =["Health Checks"])

@app.get("/")
async def root():
    return {"message": "Hello World!"} 
