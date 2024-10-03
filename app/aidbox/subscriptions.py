import uuid

from app.aidbox.sdk import sdk

@sdk.subscription("User")
async def user_created(event, request):
    sdk_settings = request.app["settings"]
    aidbox = request.app["client"]
    if event["action"] == "create":
        user = aidbox.resource("User", **event["resource"])
        if user["data"].get("resetPassword", False):
            reset_token = uuid.uuid4()
            user["data"]["reset_token"] = str(reset_token)
            await user.save()
            notification = aidbox.resource(
                "Notification",
                **{
                    "provider": "smtp-provider",
                    "providerData": {
                        "to": user["email"],
                        "subject": "Password reset",
                        "template": {
                            "id": "reset-user-password",
                            "resourceType": "NotificationTemplate",
                        },
                        "payload": {
                            "user": user.serialize(),
                            "confirm-href": f"{sdk_settings.FRONTEND_URL}/reset-password/{reset_token}",
                        },
                    },
                },
            )
            await notification.save()
            await notification.execute("$send")