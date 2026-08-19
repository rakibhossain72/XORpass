import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.templating import Jinja2Templates

from app.db.database import init_db
from app.routers import auth, vault, api

templates = Jinja2Templates(directory="templates")

def get_flashed_messages(request: Request):
    flash = request.session.pop("_flash", None)
    if flash:
        return [(flash.get("category", "info"), flash.get("message", ""))]
    return []

templates.env.globals["get_flashed_messages"] = get_flashed_messages

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(title="XORpass - Secure Password Manager", lifespan=lifespan)

SECRET_KEY = os.environ.get('SECRET_KEY', 'default-enterprise-secret-key-change-in-prod')
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="session",
    max_age=86400,
    same_site="lax",
    https_only=False
)

if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(auth.router)
app.include_router(vault.router)
app.include_router(api.router)

@app.exception_handler(404)
async def custom_404_handler(request: Request, __):
    return templates.TemplateResponse(request=request, name="404.html", status_code=404)
