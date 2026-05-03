"""
phishGPT Screenshot Worker
Polls the Flask queue for screenshot jobs, captures a headless Chrome
screenshot of the target URL, runs Tesseract OCR on the image, and
writes the base64-encoded screenshot + extracted text back to MongoDB.
"""

from datetime import datetime, timezone
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from dotenv import load_dotenv
from PIL import Image
import pytesseract
import requests
import pymongo
import logging
import base64
import numpy as np
import time
import io
import os

load_dotenv()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger("screenshot")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DB_URL = os.getenv("DB_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "gpt_app")
COLLECTION = os.getenv("DB_COLLECTION", "gpt_app")
BASE_APP = os.getenv("BASE_APP", "http://localhost:5000")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "4"))
PAGE_LOAD_WAIT = int(os.getenv("PAGE_LOAD_WAIT", "3"))

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
    """Set the screenshot_data status field (In Progress / Complete)."""
    get_collection().update_one(
        {"_id": job_id},
        {"$set": {"screenshot_data.status": status}},
    )


def save_results(job_id: str, results: dict) -> None:
    """Persist screenshot results in a single update."""
    get_collection().update_one(
        {"_id": job_id},
        {
            "$set": {
                "screenshot_data.status": "Complete",
                "screenshot_data.result": results,
                "screenshot_data.start_date": datetime.now(timezone.utc).isoformat(),
            }
        },
    )
    logger.info("job=%s screenshot results saved", job_id)


# ---------------------------------------------------------------------------
# URL extraction (handles both new and legacy redirect formats)
# ---------------------------------------------------------------------------
def _extract_url(data: dict) -> str:
    """
    Pull the final destination URL from redirect_data results.

    Handles:
      - New format:    redirect_data.result.final_url  (plain string)
      - Legacy format: redirect_data.result.final_url.url  (nested dict)
      - Fallback:      data["url"]  (original URL on the job)
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


def _build_driver() -> webdriver.Chrome:
    """Create a headless Chrome instance with safe defaults."""
    opts = Options()
    opts.add_argument("--headless")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--enable-javascript")
    opts.add_experimental_option("prefs", {
        "download.default_directory": "/dev/null",
        "download.prompt_for_download": False,
        "download.directory_upgrade": True,
        "plugins.always_open_pdf_externally": False,
    })

    service = Service(ChromeDriverManager().install())
    return webdriver.Chrome(service=service, options=opts)


def get_screenshot(url: str, job_id: str) -> tuple[str | None, str | None]:
    """
    Capture a screenshot and run OCR on it.

    Returns (ocr_text, base64_image).  Either or both may be None on failure.
    """
    url = normalise_url(url)
    driver = None

    try:
        driver = _build_driver()
        driver.set_page_load_timeout(30)
        driver.get(url)
        time.sleep(PAGE_LOAD_WAIT)  # let JS render

        encoded_image = driver.get_screenshot_as_base64()
        logger.info("job=%s screenshot captured for %s", job_id, url)
    except Exception:
        logger.exception("job=%s failed to capture screenshot for %s", job_id, url)
        return None, None
    finally:
        if driver:
            driver.quit()

    # OCR is independent – if it fails we still keep the screenshot
    ocr_text = None
    try:
        image_bytes = base64.b64decode(encoded_image)
        img = Image.open(io.BytesIO(image_bytes))
        ocr_text = pytesseract.image_to_string(np.array(img))
        logger.info("job=%s OCR extracted %d chars", job_id, len(ocr_text or ""))
    except Exception:
        logger.exception("job=%s OCR failed on screenshot", job_id)

    return ocr_text, encoded_image


# ---------------------------------------------------------------------------
# Job processor
# ---------------------------------------------------------------------------
def process_job(data: dict) -> None:
    job_id: str = data["_id"]
    url: str = _extract_url(data)

    logger.info("job=%s starting screenshot capture for %s", job_id, url)
    set_job_status(job_id, "In Progress")

    ocr_text, encoded_image = get_screenshot(url, job_id)

    results = {
        "screenshot_ocr": ocr_text,
        "encoded_screenshot": encoded_image,
    }

    save_results(job_id, results)
    logger.info("job=%s screenshot job complete – got_image=%s got_ocr=%s",
                job_id, encoded_image is not None, ocr_text is not None)


# ---------------------------------------------------------------------------
# Queue poller
# ---------------------------------------------------------------------------
def poll_queue() -> None:
    try:
        resp = requests.get(f"{BASE_APP}/screenshot_queue", timeout=10)
    except requests.RequestException:
        logger.error("Failed to reach queue API at %s", BASE_APP, exc_info=True)
        return

    if resp.status_code != 200:
        logger.error("Queue API returned status %d", resp.status_code)
        return

    data = resp.json()
    if not data:
        logger.debug("No screenshot jobs in queue")
        return

    try:
        process_job(data)
    except Exception:
        job_id = data.get("_id", "unknown")
        logger.exception("job=%s unhandled error during screenshot processing", job_id)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("Screenshot worker starting – polling every %ds", POLL_INTERVAL)
    while True:
        poll_queue()
        time.sleep(POLL_INTERVAL)