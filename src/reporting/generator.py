"""Report generator using Jinja2 templates."""
import os
from jinja2 import Environment, FileSystemLoader


class ReportGenerator:
    def __init__(self, template_dir=None):
        if template_dir is None:
            template_dir = os.path.join(os.path.dirname(__file__), "templates")
        self.env = Environment(loader=FileSystemLoader(template_dir), trim_blocks=True, lstrip_blocks=True)

    def render(self, template_name, context):
        template = self.env.get_template(template_name)
        return template.render(**context)

    def render_markdown(self, context):
        return self.render("report.md.j2", context)