"""Chargement centralisé des clés API depuis .env (jamais commité)."""
import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"

load_dotenv(ROOT / ".env")

ABUSECH_API_KEY = os.getenv("ABUSECH_API_KEY", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
HUNTIO_API_KEY = os.getenv("HUNTIO_API_KEY", "")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")


def require(name: str) -> str:
    """Renvoie la clé ou lève une erreur claire si elle est vide."""
    value = os.getenv(name, "")
    if not value:
        raise RuntimeError(f"{name} manquante : renseigne-la dans .env")
    return value
