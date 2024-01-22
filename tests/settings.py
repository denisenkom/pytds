import os
import json

CONNECT_ARGS = []
CONNECT_KWARGS = {}

connection_json_path = os.path.join(os.path.dirname(__file__), ".connection.json")

if os.path.exists(connection_json_path):
    conf = json.load(open(connection_json_path, "rb"))
    default_host = conf["host"]
    default_database = conf["database"]
    default_user = conf["sqluser"]
    default_password = conf["sqlpassword"]
    default_use_mars = conf["use_mars"]
    default_auth = conf.get("auth")
    default_cafile = conf.get("cafile")
else:
    default_host = None
    default_database = "test"
    default_user = "sa"
    default_password = "sa"
    default_use_mars = True
    default_auth = None
    default_cafile = None

LIVE_TEST = "HOST" in os.environ or default_host
if LIVE_TEST:
    HOST = os.environ.get("HOST", default_host)
    DATABASE = os.environ.get("DATABASE", default_database)
    USER = os.environ.get("SQLUSER", default_user)
    PASSWORD = os.environ.get("SQLPASSWORD", default_password)
    USE_MARS = bool(os.environ.get("USE_MARS", default_use_mars))
    SKIP_SQL_AUTH = bool(os.environ.get("SKIP_SQL_AUTH"))

    import pytds

    CONNECT_KWARGS = {
        "server": HOST,
        "database": DATABASE,
        "user": USER,
        "password": PASSWORD,
        "use_mars": USE_MARS,
        "bytes_to_unicode": True,
        "pooling": True,
        "timeout": 30,
        "cafile": default_cafile,
    }
    if default_auth:
        CONNECT_KWARGS["auth"] = getattr(pytds.login, default_auth)()

    if "tds_version" in os.environ:
        CONNECT_KWARGS["tds_version"] = getattr(pytds, os.environ["tds_version"])

    if "auth" in os.environ:
        import pytds.login

        CONNECT_KWARGS["auth"] = getattr(pytds.login, os.environ["auth"])()

    if "bytes_to_unicode" in os.environ:
        CONNECT_KWARGS["bytes_to_unicode"] = bool(os.environ.get("bytes_to_unicode"))
