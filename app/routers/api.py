from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse
import app.routers.vault as vault
import app.core.cache as cache
from app.core import tasks

router = APIRouter(prefix="/api")

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

    pwd = vault.generate_random_password(
        length=length_val,
        use_uppercase=upper_bool,
        use_lowercase=lower_bool,
        use_digits=num_bool,
        use_symbols=sym_bool
    )
    return JSONResponse({'password': pwd})

@router.get("/migration/progress")
async def migration_progress(request: Request, task_id: str = Query(...)):
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    if not tasks.task_belongs_to(task_id, user_id):
        return JSONResponse({"error": "Not found"}, status_code=404)
    return JSONResponse(tasks.get_progress(task_id))

@router.get("/cache/clear")
async def clear_cache():
    await cache.cache_clear()
    return JSONResponse({'status': 'cache cleared'})
