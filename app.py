"""
phishGPT Queue Manager - Flask API
Manages the phishing URL analysis pipeline queue backed by MongoDB.
"""

from flask import Flask, request, jsonify
from urllib.parse import urlparse, unquote
from bson.json_util import dumps, loads
from datetime import datetime, timezone
from dotenv import load_dotenv
from functools import wraps
import validators
import pymongo
import logging
import uuid
import os
import re

load_dotenv()

# ---------------------------------------------------------------------------
# Logging – structured JSON-style logs to stdout (container-friendly)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger("phishgpt")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DB_URL = os.getenv("DB_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "gpt_app")
COLLECTION = os.getenv("DB_COLLECTION", "gpt_app")


# ---------------------------------------------------------------------------
# MongoDB helper – single client with lazy init
# ---------------------------------------------------------------------------
_mongo_client: pymongo.MongoClient | None = None


def get_collection() -> pymongo.collection.Collection:
    """Return the gpt_app collection, reusing a single MongoClient."""
    global _mongo_client
    if _mongo_client is None:
        logger.info("Initializing MongoDB connection to %s", DB_URL)
        _mongo_client = pymongo.MongoClient(DB_URL, serverSelectionTimeoutMS=5000)
    return _mongo_client[DB_NAME][COLLECTION]


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------
_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)


def normalise_url(raw: str) -> str:
    """Ensure the URL has an http(s) scheme and return the normalised form."""
    raw = raw.strip()
    if not _SCHEME_RE.match(raw):
        raw = f"https://{raw}"
    return raw


def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate that *url* is a well-formed HTTP/HTTPS URL.

    Returns (is_valid, reason).
    """
    url = normalise_url(url)
    parsed = urlparse(url)

    # Scheme check
    if parsed.scheme not in ("http", "https"):
        return False, f"Unsupported scheme: {parsed.scheme}"

    # Must have a hostname
    if not parsed.hostname:
        return False, "Missing hostname"

    # Use the validators library as a secondary check
    if not (validators.url(url) or validators.domain(parsed.hostname)):
        return False, "Failed domain/URL validation"

    return True, "ok"


# ---------------------------------------------------------------------------
# Generic queue puller (eliminates repeated queue functions)
# ---------------------------------------------------------------------------

# Each pipeline stage defines the filter conditions a job must meet to be
# pulled from the queue.  Keys are the endpoint names exposed via the API.
QUEUE_STAGES: dict[str, dict] = {
    "redirect_queue": {
        "redirect_data.status": "Pending",
    },
    "net_tools_queue": {
        "net_tools_scan.status": "Pending",
        "redirect_data.status": "Complete",
    },
    "screenshot_queue": {
        "screenshot_data.status": "Pending",
        "redirect_data.status": "Complete",
    },
    "ocr_queue": {
        "ocr_data.status": "Pending",
        "redirect_data.status": "Complete",
    },
    "phishGPT_queue": {
        "ai_prompt.status": "Pending",
        "net_tools_scan.status": "Complete",
        "ocr_data.status": "Complete",
        "screenshot_data.status": "Complete",
        "redirect_data.status": "Complete",
    },
}


def pull_from_queue(stage_name: str):
    """
    Generic queue pull – looks up the filter for *stage_name* in QUEUE_STAGES,
    queries Mongo for the highest-priority pending job, and returns it.
    """
    filters = QUEUE_STAGES.get(stage_name)
    if filters is None:
        logger.error("Unknown queue stage requested: %s", stage_name)
        return jsonify({"error": f"Unknown stage: {stage_name}"}), 400

    try:
        collection = get_collection()
        data = list(
            collection.find(filters)
            .sort("priority", pymongo.ASCENDING)
            .limit(1)
        )
        result = data[0] if data else {}
    except Exception:
        logger.exception("DB error pulling from %s queue", stage_name)
        return jsonify({"error": "Database error"}), 500

    return loads(dumps(result))


# ---------------------------------------------------------------------------
# Flask app factory
# ---------------------------------------------------------------------------
def create_app() -> Flask:
    app = Flask(__name__)

    # -- Health check -------------------------------------------------------
    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    # -- Push a new URL into the pipeline -----------------------------------
    @app.post("/update")
    def push_to_queue():
        """Accept a phishing URL and queue it for the analysis pipeline."""
        try:
            data = request.get_json(force=True)
        except Exception:
            logger.warning("Malformed JSON body from %s", request.remote_addr)
            return jsonify({"error": "Invalid JSON body"}), 400

        # --- Input validation ---
        raw_url = data.get("data")
        
        if not raw_url:
            return jsonify({"error": "Missing 'data' field (URL)"}), 400

        for required in ("tag", "priority", "model"):
            print(required)
            if required not in raw_url.keys():
                return jsonify({"error": f"Missing required field: '{required}'"}), 400

        try:
            priority = int(raw_url["priority"])
        except (ValueError, TypeError):
            return jsonify({"error": "'priority' must be an integer"}), 400

        # Decode if the URL came from PhishAlarm / encoded source
        decoded_url = unquote(raw_url.get("url"))
        decoded_url = normalise_url(decoded_url)

        is_valid, reason = validate_url(decoded_url)
        if not is_valid:
            logger.info("Rejected invalid URL: %s – %s", decoded_url, reason)
            return jsonify({"error": f"Invalid URL: {reason}"}), 422

        # --- Build job document ---
        job_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        pending_block = {"status": "Pending", "result": None, "start_date": None}

        document = {
            "_id": job_id,
            "url": decoded_url,
            "source_tag": raw_url["tag"],
            "priority": priority,
            "creation_time": now,
            "ai_model": raw_url["model"],
            "redirect_data": {**pending_block},
            "net_tools_scan": {**pending_block},
            "ocr_data": {**pending_block},
            "screenshot_data": {**pending_block},
            "ai_prompt": {"status": "Pending", "decision": None, "start_date": None},
        }

        # --- Insert into Mongo ---
        try:
            collection = get_collection()
            collection.insert_one(document)
        except Exception:
            logger.exception("job=%s Failed to insert into DB", job_id)
            return jsonify({"error": "Database write failed"}), 500

        logger.info("job=%s queued url=%s priority=%d", job_id, decoded_url, priority)
        return jsonify({"status": "ok", "job_id": job_id}), 201

    # -- Queue endpoints (one route, parameterised) -------------------------
    @app.get("/queue/<stage>")
    def queue_stage(stage: str):
        """Pull the next pending job for a given pipeline stage."""
        return pull_from_queue(stage)

    # Keep the old flat paths as aliases so existing containers don't break
    for _stage in QUEUE_STAGES:

        def _make_handler(s=_stage):
            @wraps(pull_from_queue)
            def _handler():
                return pull_from_queue(s)
            return _handler

        app.add_url_rule(
            f"/{_stage}",
            endpoint=_stage,
            view_func=_make_handler(_stage),
            methods=["GET"],
        )

    # -- List all jobs ------------------------------------------------------
    @app.get("/list")
    def get_jobs():
        try:
            collection = get_collection()
            jobs = list(collection.find())
        except Exception:
            logger.exception("DB error listing jobs")
            return jsonify({"error": "Database error"}), 500

        return jsonify({"queue_count": len(jobs), "jobs": loads(dumps(jobs))})

    # -- Error handlers -----------------------------------------------------
    @app.errorhandler(404)
    def not_found(_):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def internal(_):
        return jsonify({"error": "Internal server error"}), 500

    return app


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    application = create_app()
    application.run(debug=True, port=5000, host="0.0.0.0")