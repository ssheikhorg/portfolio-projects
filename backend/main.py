import secure
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from utils import error_handler
from config import settings
from api.process_file.routes import router as process_file_router  # noqa
from api.core.issue_token_routes import router as issue_token_router  # noqa


def init_routers(app_: FastAPI) -> None:
    # include all routers here
    app_.include_router(process_file_router)
    app_.include_router(issue_token_router)


def init_exception_handlers(app_: FastAPI) -> None:
    app_.add_exception_handler(HTTPException, error_handler.http_error_handler)  # noqa
    app_.add_exception_handler(Exception, error_handler.unicorn_exception_handler)  # noqa
    app_.add_exception_handler(RequestValidationError, error_handler.request_validation_exception_handler)  # noqa
    app_.add_exception_handler(TypeError, error_handler.type_error_exception_handler)  # noqa


class SecureHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:

        # Allow Swagger UI to load without strict headers
        if request.url.path in ["/", "/openapi.json", "/docs"]:
            return await call_next(request)
            
        # Check if running locally (localhost or 127.0.0.1)
        if request.client.host in ['127.0.0.1', 'localhost']:
            return await call_next(request)

        response = await call_next(request)

        # security policies
        csp = secure.ContentSecurityPolicy() \
            .default_src("'self'") \
            .script_src("'self'", "'unsafe-inline'") \
            .style_src("'self'", "'unsafe-inline'")
        hsts = secure.StrictTransportSecurity().max_age(31536000).include_subdomains()
        referrer = secure.ReferrerPolicy().strict_origin_when_cross_origin()
        cache_value = secure.CacheControl().no_cache().no_store().max_age(0).must_revalidate()
        x_frame_options = secure.XFrameOptions().deny()

        # apply security policies
        secure_headers = secure.Secure(
            csp=csp,
            hsts=hsts,
            referrer=referrer,
            cache=cache_value,
            xfo=x_frame_options,
        )
        secure_headers.framework.fastapi(response)
        return response


def init_middleware() -> list:
    return [
        Middleware(
            CORSMiddleware,  # noqa
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
        ),
        Middleware(SecureHeadersMiddleware),  # noqa
    ]


def create_app() -> FastAPI:
    app_ = FastAPI(
        title=settings.project_name,
        description=settings.project_description,
        version="0.1.0",
        docs_url="/",
        redoc_url=None,
        middleware=init_middleware(),
    )

    init_routers(app_)
    init_exception_handlers(app_)

    return app_


app = create_app()
