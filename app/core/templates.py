import os
from jinja2 import Environment, FileSystemLoader

class DynamicTemplates:
    def __init__(self, directory: str = "templates"):
        self.directory = directory

    def TemplateResponse(self, request, name: str, context: dict = None, status_code: int = 200, **kwargs):
        if context is None:
            context = {}

        # Fresh Jinja Environment per render to avoid cached global state issues
        env = Environment(loader=FileSystemLoader(self.directory), autoescape=True)

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

        env.globals["get_flashed_messages"] = get_flashed_messages

        render_context = {"request": request, **context}
        template = env.get_template(name)
        content = template.render(render_context)

        from fastapi.responses import HTMLResponse
        return HTMLResponse(content=content, status_code=status_code)
