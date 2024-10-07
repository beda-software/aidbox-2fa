from os import environ

TWO_FACTOR_ISSUER_NAME = environ["TWO_FACTOR_ISSUER_NAME"]
TWO_FACTOR_VALID_PAST_TOKENS_COUNT = int(environ.get("TWO_FACTOR_VALID_PAST_TOKENS_COUNT", "5"))
TWO_FACTOR_WEBHOOK_URL = environ["TWO_FACTOR_WEBHOOK_URL"]
TWO_FACTOR_WEBHOOK_AUTHORIZATION = environ["TWO_FACTOR_WEBHOOK_AUTHORIZATION"]