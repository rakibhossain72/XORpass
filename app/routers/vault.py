import re
import secrets
import string
from fastapi import APIRouter, Request, Form, Query, Depends, status
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from werkzeug.security import generate_password_hash, check_password_hash

from app.db.database import get_db
import app.db.crud as crud
import app.core.encryption as encryption
import app.core.cache as cache
from app.core.templates import DynamicTemplates

router = APIRouter()
templates = DynamicTemplates(directory="templates")

def set_flash(request: Request, message: str, category: str = "danger"):
    request.session["_flash"] = {"message": message, "category": category}

def password_strength(password: str) -> str:
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[!@#$%^&*()-+=]", password):
        score += 1

    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Medium"
    else:
        return "Strong"

def generate_random_password(length=16, use_uppercase=True, use_lowercase=True, use_digits=True, use_symbols=True):
    chars = ""
    if use_uppercase:
        chars += string.ascii_uppercase
    if use_lowercase:
        chars += string.ascii_lowercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += "!@#$%^&*()-+=_[]{}|;:,.<>?"
    if not chars:
        chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

@router.get("/", response_class=HTMLResponse)
async def home(request: Request, db: AsyncSession = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    user = await crud.get_user_by_email(db, user_id)
    if not user:
        request.session.pop("user_id", None)
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    # Check cache for user password entries
    cache_key = f"user_entries:{user_id}"
    cached_entries = await cache.cache_get(cache_key)
    if cached_entries is not None:
        data = cached_entries
    else:
        entries = await crud.get_password_entries_by_owner(db, user_id)
        data = [
            {
                "id": entry.id,
                "_id": entry.id,
                "website": entry.website,
                "email": entry.email,
                "password": entry.password,
                "owner_id": entry.owner_id,
                "difficulty": entry.difficulty
            }
            for entry in entries
        ]
        await cache.cache_set(cache_key, data, ttl=60)

    user_dict = {
        "email": user.email,
        "password": user.password,
        "public_key": user.public_key,
        "private_key": user.private_key
    }
    return templates.TemplateResponse(request=request, name="home.html", context={"user": user_dict, "data": data})

@router.get("/add", response_class=HTMLResponse)
async def add_page(request: Request):
    if not request.session.get("user_id"):
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request=request, name="add.html", context={})

@router.post("/add")
async def add_action(
    request: Request,
    website: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    clean_website = website.strip()
    clean_email = email.strip()

    user_data = await crud.get_user_by_email(db, user_id)
    if not user_data:
        request.session.pop("user_id", None)
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    existing_entries = await crud.get_password_entries_by_owner(db, user_id)
    for d in existing_entries:
        if d.website == clean_website and d.email == clean_email:
            set_flash(request, "An entry for this website and email already exists", "danger")
            return RedirectResponse(url="/add", status_code=status.HTTP_302_FOUND)

    encrypted_password = encryption.encode_data(password, user_data.public_key)
    difficulty = password_strength(password)
    await crud.add_password_entry(db, clean_website, clean_email, encrypted_password, user_id, difficulty)

    # Invalidate user cache
    await cache.cache_delete(f"user_entries:{user_id}")

    set_flash(request, "Password added successfully", "success")
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

@router.post("/edit")
async def edit_legacy(
    request: Request,
    id: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    data_entry = await crud.get_password_entry_by_id(db, id)
    if not data_entry or data_entry.owner_id != user_id:
        set_flash(request, "Unauthorized access or entry not found", "danger")
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    user_data = await crud.get_user_by_email(db, user_id)
    if not user_data or not check_password_hash(user_data.password, password):
        set_flash(request, "Invalid master password", "danger")
        return RedirectResponse(url=f"/decrypt/{id}", status_code=status.HTTP_302_FOUND)

    try:
        decoded_key = encryption.decode_key(user_data.private_key, password)
        decrypted_pwd = encryption.decode_data(data_entry.password, decoded_key)
    except Exception:
        set_flash(request, "Failed to decrypt stored password. Master password may be incorrect.", "danger")
        return RedirectResponse(url=f"/decrypt/{id}", status_code=status.HTTP_302_FOUND)

    entry_dict = {
        "id": data_entry.id,
        "_id": data_entry.id,
        "website": data_entry.website,
        "email": data_entry.email,
        "password": decrypted_pwd,
        "owner_id": data_entry.owner_id,
        "difficulty": data_entry.difficulty
    }
    return templates.TemplateResponse(request=request, name="edit.html", context={"data": entry_dict})

@router.post("/edit/{doc_id}")
async def update_entry(
    request: Request,
    doc_id: str,
    website: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    data_entry = await crud.get_password_entry_by_id(db, doc_id)
    if not data_entry or data_entry.owner_id != user_id:
        set_flash(request, "Unauthorized access or entry not found", "danger")
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    user_data = await crud.get_user_by_email(db, user_id)

    encrypted_password = encryption.encode_data(password, user_data.public_key)
    difficulty = password_strength(password)

    updated_fields = {
        "website": website.strip(),
        "email": email.strip(),
        "password": encrypted_password,
        "difficulty": difficulty,
        "owner_id": user_id
    }
    await crud.update_password_entry(db, doc_id, updated_fields)
    await cache.cache_delete(f"user_entries:{user_id}")

    set_flash(request, "Password updated successfully", "success")
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

@router.get("/decrypt/{doc_id}", response_class=HTMLResponse)
async def decrypt_page(request: Request, doc_id: str, db: AsyncSession = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    data_entry = await crud.get_password_entry_by_id(db, doc_id)
    if not data_entry or data_entry.owner_id != user_id:
        set_flash(request, "Unauthorized access or entry not found", "danger")
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse(request=request, name="decrypt.html", context={"id": doc_id})

@router.post("/decrypt/{doc_id}")
async def decrypt_action(
    request: Request,
    doc_id: str,
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    data_entry = await crud.get_password_entry_by_id(db, doc_id)
    if not data_entry or data_entry.owner_id != user_id:
        set_flash(request, "Unauthorized access or entry not found", "danger")
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    user_data = await crud.get_user_by_email(db, user_id)
    if not user_data or not check_password_hash(user_data.password, password):
        set_flash(request, "Invalid password", "danger")
        return RedirectResponse(url=f"/decrypt/{doc_id}", status_code=status.HTTP_302_FOUND)

    try:
        decoded_key = encryption.decode_key(user_data.private_key, password)
        decrypted_pwd = encryption.decode_data(data_entry.password, decoded_key)
    except Exception:
        set_flash(request, "Failed to decrypt password", "danger")
        return RedirectResponse(url=f"/decrypt/{doc_id}", status_code=status.HTTP_302_FOUND)

    entry_dict = {
        "id": data_entry.id,
        "_id": data_entry.id,
        "website": data_entry.website,
        "email": data_entry.email,
        "password": decrypted_pwd,
        "owner_id": data_entry.owner_id,
        "difficulty": data_entry.difficulty
    }
    return templates.TemplateResponse(request=request, name="edit.html", context={"data": entry_dict})

@router.post("/delete")
async def delete_action(
    request: Request,
    id: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    data_entry = await crud.get_password_entry_by_id(db, id)
    if not data_entry or data_entry.owner_id != user_id:
        set_flash(request, "Unauthorized access or entry not found", "danger")
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    await crud.delete_password_entry(db, id)
    await cache.cache_delete(f"user_entries:{user_id}")

    set_flash(request, "Password deleted successfully", "success")
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    if not request.session.get("user_id"):
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request=request, name="settings.html", context={})

@router.post("/settings")
async def settings_action(
    request: Request,
    password: str = Form(...),
    new_password: str = Form(...),
    confirm_new_password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    user_data = await crud.get_user_by_email(db, user_id)
    if not user_data or not check_password_hash(user_data.password, password):
        set_flash(request, "Invalid current password", "danger")
        return RedirectResponse(url="/settings", status_code=status.HTTP_302_FOUND)

    if new_password != confirm_new_password:
        set_flash(request, "Passwords do not match", "danger")
        return RedirectResponse(url="/settings", status_code=status.HTTP_302_FOUND)

    if len(new_password) < 8 or len(new_password) > 64:
        set_flash(request, "Password must be between 8 and 64 characters long", "danger")
        return RedirectResponse(url="/settings", status_code=status.HTTP_302_FOUND)

    if not any(char.isdigit() for char in new_password):
        set_flash(request, "Password must contain at least one number", "danger")
        return RedirectResponse(url="/settings", status_code=status.HTTP_302_FOUND)

    if not any(char.isupper() for char in new_password):
        set_flash(request, "Password must contain at least one uppercase letter", "danger")
        return RedirectResponse(url="/settings", status_code=status.HTTP_302_FOUND)

    if not any(char.islower() for char in new_password):
        set_flash(request, "Password must contain at least one lowercase letter", "danger")
        return RedirectResponse(url="/settings", status_code=status.HTTP_302_FOUND)

    if any(char.isspace() for char in new_password):
        set_flash(request, "Password must not contain any spaces", "danger")
        return RedirectResponse(url="/settings", status_code=status.HTTP_302_FOUND)

    if new_password == password:
        set_flash(request, "New password cannot be the same as the old password", "danger")
        return RedirectResponse(url="/settings", status_code=status.HTTP_302_FOUND)

    try:
        private_key = encryption.decode_key(user_data.private_key, password)
        new_private_key_enc = encryption.encode_key(new_password, private_key=private_key)[1]
        new_password_hash = generate_password_hash(new_password)

        updated_fields = {
            "private_key": new_private_key_enc,
            "password": new_password_hash
        }
        await crud.update_user(db, user_id, updated_fields)
        set_flash(request, "Master password updated successfully", "success")
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    except Exception:
        set_flash(request, "Failed to update master password", "danger")
        return RedirectResponse(url="/settings", status_code=status.HTTP_302_FOUND)

@router.get("/generate-password")
async def generate_password_api(
    length: int = Query(16),
    symbols: str = Query("true"),
    numbers: str = Query("true"),
    uppercase: str = Query("true"),
    lowercase: str = Query("true")
):
    length_val = max(8, min(length, 64))
    sym_bool = symbols.lower() == 'true'
    num_bool = numbers.lower() == 'true'
    upper_bool = uppercase.lower() == 'true'
    lower_bool = lowercase.lower() == 'true'

    pwd = generate_random_password(
        length=length_val,
        use_uppercase=upper_bool,
        use_lowercase=lower_bool,
        use_digits=num_bool,
        use_symbols=sym_bool
    )
    return JSONResponse({'password': pwd})
