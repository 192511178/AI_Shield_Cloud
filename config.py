import os

MYSQL_HOST = os.environ.get("MYSQLHOST")
MYSQL_USER = os.environ.get("MYSQLUSER")
MYSQL_PASSWORD = os.environ.get("MYSQLPASSWORD")
MYSQL_DB = os.environ.get("MYSQLDATABASE")
MYSQL_PORT = int(os.environ.get("MYSQLPORT", 3306))

SECRET_KEY = "aishieldsecretkey"
EMAIL = "mohammedsyedthowfiq21@gmail.com"
APP_PASSWORD = "hexu ozqg wvrq haku"