import os
import secrets
from jinja2 import Environment, FileSystemLoader

class DynamicTemplates:
    def __init__(self, directory: str = "templates"):
        self.directory = directory

    def TemplateResponse(self, request, name: str, context: dict = None, status_code: int = 200, **kwargs):
        if context is None:
            context = {}

        # Fresh Jinja Environment per render to avoid cached global state issues
        env = Environment(loader=FileSystemLoader(self.directory), autoescape=True)

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

        env.globals["csrf_token"] = csrf_token
        env.globals["get_flashed_messages"] = get_flashed_messages

        render_context = {"request": request, **context}
        template = env.get_template(name)
        content = template.render(render_context)

        from fastapi.responses import HTMLResponse
        return HTMLResponse(content=content, status_code=status_code)
