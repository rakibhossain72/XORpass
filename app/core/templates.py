import os
import secrets
from jinja2 import Environment, FileSystemLoader

class DynamicTemplates:
    def __init__(self, directory: str = "templates"):
        self.directory = directory
        self.env = Environment(loader=FileSystemLoader(directory), autoescape=True)

    def TemplateResponse(self, request, name: str, context: dict = None, status_code: int = 200, **kwargs):
        if context is None:
            context = {}

        def csrf_token():
            token = request.session.get("_csrf_token")
            if not token:
                token = secrets.token_hex(32)
                request.session["_csrf_token"] = token
            return token

        def get_flashed_messages(with_categories: bool = False, category_filter: list = ()):
            flash = request.session.pop("_flash", None)
            if not flash:
                return []
            msg = flash.get("message", "")
            cat = flash.get("category", "info")
            if category_filter and cat not in category_filter:
                return []
            if with_categories:
                return [(cat, msg)]
            return [msg]

        render_context = {
            "request": request,
            "csrf_token": csrf_token,
            "get_flashed_messages": get_flashed_messages,
            **context,
        }
        template = self.env.get_template(name)
        content = template.render(render_context)

        from fastapi.responses import HTMLResponse
        return HTMLResponse(content=content, status_code=status_code)
