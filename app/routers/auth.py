import re
from fastapi import APIRouter, Request, Form, Depends, status
from fastapi.responses import RedirectResponse, HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from werkzeug.security import generate_password_hash, check_password_hash

from app.db.database import get_db
import app.db.crud as crud
import app.core.encryption as encryption
from app.core.templates import DynamicTemplates

router = APIRouter()
templates = DynamicTemplates(directory="templates")

def set_flash(request: Request, message: str, category: str = "danger"):
    request.session["_flash"] = {"message": message, "category": category}

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request=request, name="login.html", context={})

@router.post("/login")
async def login_action(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    if request.session.get("user_id"):
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    clean_email = email.strip()
    db_user = await crud.get_user_by_email(db, clean_email)
    if db_user and check_password_hash(db_user.password, password):
        request.session["user_id"] = clean_email
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    else:
        set_flash(request, "Invalid email or password", "danger")
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

@router.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request=request, name="signup.html", context={})

@router.post("/signup")
async def signup_action(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(..., alias="confirm-password"),
    db: AsyncSession = Depends(get_db)
):
    if request.session.get("user_id"):
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    clean_email = email.strip()
    if not clean_email:
        set_flash(request, "Email is required", "danger")
        return RedirectResponse(url="/signup", status_code=status.HTTP_302_FOUND)

    if password != confirm_password:
        set_flash(request, "Passwords do not match", "danger")
        return RedirectResponse(url="/signup", status_code=status.HTTP_302_FOUND)

    if len(password) < 8 or len(password) > 64:
        set_flash(request, "Password must be between 8 and 64 characters long", "danger")
        return RedirectResponse(url="/signup", status_code=status.HTTP_302_FOUND)

    if not any(char.isdigit() for char in password):
        set_flash(request, "Password must contain at least one number", "danger")
        return RedirectResponse(url="/signup", status_code=status.HTTP_302_FOUND)

    if not any(char.isupper() for char in password):
        set_flash(request, "Password must contain at least one uppercase letter", "danger")
        return RedirectResponse(url="/signup", status_code=status.HTTP_302_FOUND)

    if not any(char.islower() for char in password):
        set_flash(request, "Password must contain at least one lowercase letter", "danger")
        return RedirectResponse(url="/signup", status_code=status.HTTP_302_FOUND)

    if any(char.isspace() for char in password):
        set_flash(request, "Password must not contain any spaces", "danger")
        return RedirectResponse(url="/signup", status_code=status.HTTP_302_FOUND)

    existing_user = await crud.get_user_by_email(db, clean_email)
    if existing_user:
        set_flash(request, "Email already exists", "danger")
        return RedirectResponse(url="/signup", status_code=status.HTTP_302_FOUND)

    public_key, private_key = encryption.encode_key(password)
    password_hash = generate_password_hash(password)
    await crud.create_user(db, clean_email, password_hash, public_key, private_key)

    request.session["user_id"] = clean_email
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

@router.get("/logout")
async def logout(request: Request):
    request.session.pop("user_id", None)
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
