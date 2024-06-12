import secure
from config import settings
from fastapi import APIRouter, Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .process_file_routes import router as process_file_router
from .retrieve_processed_file_routes import router as retrieve_file_router
from .signal_file_processed_routes import router as signal_file_router

app = FastAPI(
    title=settings.project_name,
    description=settings.project_description,
)

csp = secure.ContentSecurityPolicy().default_src("'self'").frame_ancestors("'none'")
hsts = secure.StrictTransportSecurity().max_age(31536000).include_subdomains()
referrer = secure.ReferrerPolicy().no_referrer()
cache_value = secure.CacheControl().no_cache().no_store().max_age(0).must_revalidate()
x_frame_options = secure.XFrameOptions().deny()

secure_headers = secure.Secure(
    csp=csp,
    hsts=hsts,
    referrer=referrer,
    cache=cache_value,
    xfo=x_frame_options,
)
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    message = str(exc.detail)

    return JSONResponse({"message": message}, status_code=exc.status_code)


@app.get("/", name="docs")
def main():
    return RedirectResponse(url="/docs/")


file_service_router = APIRouter(prefix="/file_service")
file_service_router.include_router(process_file_router)
file_service_router.include_router(signal_file_router)
file_service_router.include_router(retrieve_file_router)
