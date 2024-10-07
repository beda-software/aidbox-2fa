import datetime

import pyotp
from aiohttp import web, ClientSession
from pyotp.utils import strings_equal
from aidbox_python_sdk.types import SDKOperation, SDKOperationRequest
from aidbox_python_sdk import app_keys as ak
from aidbox_python_sdk.aidboxpy import AsyncAidboxClient, AsyncAidboxResource

from app.sdk import sdk
from app.utils import get_error_payload
from app import config


@sdk.operation(["POST"], ["app", "auth", "two-factor", "request"])
async def auth_two_factor_request_op(_operation: SDKOperation, request: SDKOperationRequest):
    client = request["app"][ak.client]
    # TODO: think about throttling based on User.ts
    user = await client.resources("User").search(_id=request["oauth/user"]["id"]).get() # type: ignore

    if user.get_by_path(["twoFactor", "enabled"]):
        return web.json_response(
            get_error_payload("2FA is already enabled", code="already_enabled"),
            status=422,
        )

    secret_key = pyotp.random_base32()

    resource = request.get("resource", {})
    transport = resource.get("transport")

    user["twoFactor"] = {
        "enabled": False,
        "secretKey": secret_key,
        "transport": transport,
    }
    await user.save()

    if transport:
        token = generate_token(secret_key)

        await send_confirmation_token(client, user, token)
        return web.json_response({})

    uri = pyotp.totp.TOTP(secret_key).provisioning_uri(
        name=user["email"], issuer_name=config.TWO_FACTOR_ISSUER_NAME
    )

    return web.json_response({"uri": uri})


@sdk.operation(["POST"], ["app", "auth", "two-factor", "confirm"])
async def auth_two_factor_confirm_op(_operation: SDKOperation, request: SDKOperationRequest):
    client = request["app"][ak.client]
    user = await client.resources("User").search(_id=request["oauth/user"]["id"]).get() # type: ignore
    if not user.get("twoFactor"):
        return web.json_response(
            get_error_payload("2FA is not requested", code="not_requested"), status=422
        )

    if user["twoFactor"]["enabled"]:
        return web.json_response(
            get_error_payload("2FA is already enabled", code="already_enabled"),
            status=422,
        )

    secret_key = user["twoFactor"]["secretKey"]
    token = request["resource"].get("token")

    if not verify_token(secret_key, token):
        return web.json_response(
            get_error_payload("Wrong token", code="wrong_token"), status=422
        )

    user["twoFactor"]["enabled"] = True
    await user.save()

    return web.json_response({})


def generate_token(secret_key):
    totp = pyotp.totp.TOTP(secret_key)
    return totp.now()


def verify_token(secret_key, token):
    """Validates token considering past tokens"""
    if not token:
        return False

    totp = pyotp.totp.TOTP(secret_key)

    for_time = datetime.datetime.now()

    for i in range(-config.TWO_FACTOR_VALID_PAST_TOKENS_COUNT, 1):
        if strings_equal(str(token), str(totp.at(for_time, i))):
            return True
    return False


async def send_confirmation_token(client: AsyncAidboxClient, user: AsyncAidboxResource, token: str):
    async with ClientSession() as session:
        async with session.post(
                config.TWO_FACTOR_WEBHOOK_URL,
                headers={"Authorization": config.TWO_FACTOR_WEBHOOK_AUTHORIZATION},
                json={
                    "user": user.serialize(),
                    "token": token,
                },
            ) as response:
                if response.status != 200:
                    raise web.HTTPInternalServerError(
                        text=await response.text()
                    )
