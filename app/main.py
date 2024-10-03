from aidbox_python_sdk.main import create_app
from aiohttp import web

from app.aidbox.sdk import sdk

async def application() -> web.Application:
    app = create_app(sdk)
    return app