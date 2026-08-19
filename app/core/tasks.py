import uuid
from typing import Dict, Any

_tasks: Dict[str, Dict[str, Any]] = {}

_active_by_user: Dict[str, str] = {}

def create_task(user_id: str) -> str:
    task_id = str(uuid.uuid4())
    _tasks[task_id] = {
        "status": "running",
        "progress": 0,
        "total": 0,
        "current": 0,
        "error": None,
        "user_id": user_id,
    }
    _active_by_user[user_id] = task_id
    return task_id

def update_progress(task_id: str, current: int, total: int):
    if task_id in _tasks:
        _tasks[task_id]["current"] = current
        _tasks[task_id]["total"] = total
        _tasks[task_id]["progress"] = int((current / total) * 100) if total > 0 else 100

def complete_task(task_id: str):
    if task_id in _tasks:
        _tasks[task_id]["status"] = "completed"
        _tasks[task_id]["progress"] = 100
        user_id = _tasks[task_id].get("user_id")
        if user_id and _active_by_user.get(user_id) == task_id:
            del _active_by_user[user_id]

def fail_task(task_id: str, error: str):
    if task_id in _tasks:
        _tasks[task_id]["status"] = "failed"
        _tasks[task_id]["error"] = error
        user_id = _tasks[task_id].get("user_id")
        if user_id and _active_by_user.get(user_id) == task_id:
            del _active_by_user[user_id]

def get_progress(task_id: str) -> Dict[str, Any]:
    task = _tasks.get(task_id)
    if not task:
        return {"status": "not_found"}
    return {
        "status": task["status"],
        "progress": task["progress"],
        "total": task["total"],
        "current": task["current"],
        "error": task["error"],
    }

def is_active(user_id: str) -> bool:
    task_id = _active_by_user.get(user_id)
    if not task_id:
        return False
    task = _tasks.get(task_id)
    return task is not None and task["status"] == "running"

def task_belongs_to(task_id: str, user_id: str) -> bool:
    task = _tasks.get(task_id)
    return task is not None and task.get("user_id") == user_id
