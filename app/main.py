from aidbox_python_sdk.main import create_app
from aiohttp import web

from app.sdk import sdk
from app import operations

import logging

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)

async def application() -> web.Application:
    app = create_app(sdk)
    return app