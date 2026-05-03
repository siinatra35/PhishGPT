"""
phishGPT Site OCR Worker
Polls the Flask queue for OCR jobs, extracts visible text from the
target webpage using trafilatura, and writes results back to MongoDB.
"""

from datetime import datetime, timezone
from trafilatura import fetch_url, extract
from dotenv import load_dotenv
import pymongo
import logging
import time
import os
import requests

load_dotenv()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger("site_ocr")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DB_URL = os.getenv("DB_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "gpt_app")
COLLECTION = os.getenv("DB_COLLECTION", "gpt_app")
BASE_APP = os.getenv("BASE_APP", "http://localhost:5000")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "4"))

# ---------------------------------------------------------------------------
# MongoDB – single reusable client
# ---------------------------------------------------------------------------
_mongo_client: pymongo.MongoClient | None = None


def get_collection() -> pymongo.collection.Collection:
    global _mongo_client
    if _mongo_client is None:
        logger.info("Connecting to MongoDB at %s", DB_URL)
        _mongo_client = pymongo.MongoClient(DB_URL, serverSelectionTimeoutMS=5000)
    return _mongo_client[DB_NAME][COLLECTION]


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
def set_job_status(job_id: str, status: str) -> None:
    """Set the ocr_data status field (In Progress / Complete)."""
    get_collection().update_one(
        {"_id": job_id},
        {"$set": {"ocr_data.status": status}},
    )


def save_results(job_id: str, ocr_text: str | None) -> None:
    """Persist OCR results in a single update."""
    get_collection().update_one(
        {"_id": job_id},
        {
            "$set": {
                "ocr_data.status": "Complete",
                "ocr_data.result": ocr_text,
                "ocr_data.start_date": datetime.now(timezone.utc).isoformat(),
            }
        },
    )
    logger.info("job=%s OCR results saved", job_id)


# ---------------------------------------------------------------------------
# URL extraction (handles both new and legacy redirect formats)
# ---------------------------------------------------------------------------
def _extract_url(data: dict) -> str:
    """
    Pull the final destination URL from redirect_data results.

    Handles:
      - New format:   redirect_data.result.final_url  (plain string)
      - Legacy format: redirect_data.result.final_url.url  (nested dict)
      - Fallback:     data["url"]  (original URL on the job)
    """
    redirect = data.get("redirect_data", {})
    result = redirect.get("result") if isinstance(redirect, dict) else None

    if isinstance(result, dict):
        final = result.get("final_url")
        if isinstance(final, str) and final:
            return final
        if isinstance(final, dict):
            nested = final.get("url")
            if isinstance(nested, str) and nested:
                return nested

    fallback = data.get("url", "")
    if fallback:
        logger.warning(
            "job=%s redirect result missing or malformed – falling back to original URL: %s",
            data.get("_id", "unknown"), fallback,
        )
        return fallback

    raise ValueError(f"job={data.get('_id')} has no usable URL in redirect_data or top-level 'url' field")


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------
def normalise_url(url: str) -> str:
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        url = f"https://{url}"
    return url


def get_ocr(url: str, job_id: str) -> str | None:
    """
    Fetch the page at *url* and extract its visible text.
    Returns the extracted text, or None on failure.
    """
    url = normalise_url(url)
    try:
        html = fetch_url(url)
        if html is None:
            logger.warning("job=%s trafilatura returned no HTML for %s", job_id, url)
            return None

        text = extract(html)
        if text:
            logger.info("job=%s extracted %d chars from %s", job_id, len(text), url)
        else:
            logger.warning("job=%s no text extracted from %s", job_id, url)
        return text

    except Exception:
        logger.exception("job=%s OCR failed for %s", job_id, url)
        return None


# ---------------------------------------------------------------------------
# Job processor
# ---------------------------------------------------------------------------
def process_job(data: dict) -> None:
    job_id: str = data["_id"]
    url: str = _extract_url(data)

    logger.info("job=%s starting OCR on %s", job_id, url)
    set_job_status(job_id, "In Progress")

    ocr_text = get_ocr(url, job_id)

    save_results(job_id, ocr_text)
    logger.info("job=%s OCR complete – got_text=%s", job_id, ocr_text is not None)


# ---------------------------------------------------------------------------
# Queue poller
# ---------------------------------------------------------------------------
def poll_queue() -> None:
    try:
        resp = requests.get(f"{BASE_APP}/ocr_queue", timeout=10)
    except requests.RequestException:
        logger.error("Failed to reach queue API at %s", BASE_APP, exc_info=True)
        return

    if resp.status_code != 200:
        logger.error("Queue API returned status %d", resp.status_code)
        return

    data = resp.json()
    if not data:
        logger.debug("No OCR jobs in queue")
        return

    try:
        process_job(data)
    except Exception:
        job_id = data.get("_id", "unknown")
        logger.exception("job=%s unhandled error during OCR processing", job_id)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("OCR worker starting – polling every %ds", POLL_INTERVAL)
    while True:
        poll_queue()
        time.sleep(POLL_INTERVAL)