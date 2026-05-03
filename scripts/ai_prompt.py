"""
phishGPT AI Prompt Worker
Polls the Flask queue for prompt jobs, assembles enrichment data into
a phishing analysis prompt, sends it to either the Claude API or a
local Ollama instance for a verdict, and writes the decision back to
MongoDB.  Optionally notifies Discord.

Configuration (env vars):
  AI_BACKEND        – "claude" or "ollama"  (default: ollama)
  ANTHROPIC_API_KEY – required when AI_BACKEND=claude
  CLAUDE_MODEL      – Claude model to use   (default: claude-sonnet-4-20250514)
  OLLAMA_HOST       – Ollama server URL     (default: http://localhost:11434)
  OLLAMA_MODEL      – Ollama model to use   (default: llama3.3)

The backend can also be overridden per-job via the "ai_model" field in
the job document.  If the value starts with "claude" it routes to the
Claude API; anything else routes to Ollama.
"""

from datetime import datetime, timezone
from dotenv import load_dotenv
import requests
import pymongo
import logging
import json
import time
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
logger = logging.getLogger("prompt")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DB_URL = os.getenv("DB_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "gpt_app")
COLLECTION = os.getenv("DB_COLLECTION", "gpt_app")
BASE_APP = os.getenv("BASE_APP", "http://localhost:5000")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "4"))

# AI backend selection: "claude" or "ollama"
AI_BACKEND = os.getenv("AI_BACKEND", "ollama").lower()

# Claude settings
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")

# Ollama settings
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.3")

# Discord
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

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
    """Set the ai_prompt status field (In Progress / Complete)."""
    get_collection().update_one(
        {"_id": job_id},
        {"$set": {"ai_prompt.status": status}},
    )


def save_results(job_id: str, decision: dict | None, backend_used: str) -> None:
    """Persist AI decision in a single update."""
    get_collection().update_one(
        {"_id": job_id},
        {
            "$set": {
                "ai_prompt.status": "Complete",
                "ai_prompt.decision": decision,
                "ai_prompt.backend": backend_used,
                "ai_prompt.start_date": datetime.now(timezone.utc).isoformat(),
            }
        },
    )
    logger.info("job=%s AI decision saved (backend=%s)", job_id, backend_used)


# ---------------------------------------------------------------------------
# URL extraction (handles both new and legacy redirect formats)
# ---------------------------------------------------------------------------
def _extract_redirect_urls(data: dict) -> tuple[str, str]:
    redirect = data.get("redirect_data", {})
    result = redirect.get("result") if isinstance(redirect, dict) else None
    fallback = data.get("url", "")

    if not isinstance(result, dict):
        return fallback, fallback

    def _get_url(key: str) -> str:
        val = result.get(key)
        if isinstance(val, str) and val:
            return val
        if isinstance(val, dict):
            nested = val.get("url")
            if isinstance(nested, str) and nested:
                return nested
        return fallback

    return _get_url("starting_url"), _get_url("final_url")


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------
def _safe_get(data: dict, *keys, default=None):
    """Walk nested keys safely, returning *default* if anything is missing."""
    current = data
    for k in keys:
        if isinstance(current, dict):
            current = current.get(k)
        else:
            return default
    return current if current is not None else default


def create_prompt(data: dict) -> str:
    """Assemble all enrichment data into the phishing analysis prompt."""
    start_url, final_url = _extract_redirect_urls(data)

    ocr_text = _safe_get(data, "ocr_data", "result", default="No OCR data available")
    screenshot_ocr = _safe_get(data, "screenshot_data", "result", "screenshot_ocr",
                               default="No screenshot OCR data available")

    net_tools = _safe_get(data, "net_tools_scan", "result", default={})
    net_tools_str = json.dumps(net_tools, indent=4, default=str) if net_tools else "No net tools data available"

    headers_info = _safe_get(data, "redirect_data", "result", "response_headers", default=None)
    if headers_info is None:
        headers_info = _safe_get(data, "redirect_data", "result", "respose_headers", default=None)
    headers_str = json.dumps(headers_info, indent=4) if headers_info else "No header data available"

    return f"""
You are a web programmer and security expert tasked with examining a web page to determine if it is a phishing site or a legitimate site. To complete this task, follow these sub-tasks:

1. Analyze the HTML, URL, and OCR-extracted text for any social engineering techniques often used in phishing attacks. Point out any suspicious elements found in the HTML, URL, or text.
2. Identify the brand name. If the HTML appears to resemble a legitimate web page, verify if the URL matches the legitimate domain name associated with the brand, if known.
3. State your conclusion on whether the site is a phishing site or a legitimate one, and explain your reasoning. If there is insufficient evidence to make a determination, answer "unknown".
4. Submit your findings as JSON-formatted output with the following keys:
- phishing_score: int (indicates phishing risk on a scale of 0 to 10)
- brands: str (identified brand name or None if not applicable)
- phishing: boolean (whether the site is a phishing site or a legitimate site)
- suspicious_domain: boolean (whether the domain name is suspected to be not legitimate)
- reasoning: string (explains your reasoning for your conclusion on whether the site is a phishing site or a legitimate in 4 to 5 sentences)

Limitations:
- The HTML may be shortened and simplified.
- The OCR-extracted text may not always be accurate.
- Screenshot OCR may contain an error message, if so ignore error and continue with url investigation.
- The HTML and OCR-extracted text may overlap and be partially duplicated.
- The net tools data will be in the form of a dictionary.
- If the url is determined to be a tracking url then there is a probability that it will be used for marketing as this url was pulled from an email our users received.
- Take note of the response headers, mainly the content type as it may be a hosted image, gif, etc.

Examples of social engineering techniques and other key items to search for:
- Alerting the user to a problem with their account
- Offering unexpected rewards
- Informing the user of a missing package or additional payment required
- Displaying fake security warnings
- Using website builders or hosting services that mimic a login page of a well known brand
- Suspicious subdomain being used with a website builder service
- The webpage contents are trying to mimic a well known brand that's unrelated to the website host

STARTING URL:
{start_url}

FINAL DESTINATION URL:
{final_url}

EXTRACTED TEXT FROM WEBSITE:
```
{ocr_text}
```

WEBSITE SCREENSHOT EXTRACTED TEXT:
```
{screenshot_ocr}
```

NET TOOLS ENUMERATION DATA:
```
{net_tools_str}
```

RESPONSE HEADERS:
{headers_str}

Respond ONLY with the JSON object described above. No additional text.
"""


# ---------------------------------------------------------------------------
# Response parser (shared by both backends)
# ---------------------------------------------------------------------------
EXPECTED_KEYS = {"phishing_score", "brands", "phishing", "suspicious_domain", "reasoning"}


def _parse_ai_response(raw: str, job_id: str) -> dict | None:
    """
    Parse the raw LLM response into the expected JSON schema.
    Strips markdown fences, validates required keys.
    """
    cleaned = raw.strip()

    if cleaned.startswith("```"):
        cleaned = cleaned.removeprefix("```json").removeprefix("```")
    if cleaned.endswith("```"):
        cleaned = cleaned.removesuffix("```")
    cleaned = cleaned.strip()

    try:
        decision = json.loads(cleaned)
    except json.JSONDecodeError:
        logger.error("job=%s failed to parse AI response as JSON: %.500s", job_id, raw)
        return None

    missing = EXPECTED_KEYS - set(decision.keys())
    if missing:
        logger.warning("job=%s AI response missing keys: %s", job_id, ", ".join(missing))

    return decision


# ---------------------------------------------------------------------------
# Backend: Claude API
# ---------------------------------------------------------------------------
def ask_claude(prompt: str, job_id: str, model: str | None = None) -> dict | None:
    """Send prompt to Claude API. Returns parsed decision or None."""
    try:
        import anthropic
    except ImportError:
        logger.error("job=%s anthropic package not installed – run: pip install anthropic", job_id)
        return None

    if not ANTHROPIC_API_KEY:
        logger.error("job=%s ANTHROPIC_API_KEY is not set", job_id)
        return None

    model = model or CLAUDE_MODEL
    logger.info("job=%s sending prompt to Claude (%s)", job_id, model)

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        message = client.messages.create(
            model=model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = message.content[0].text
    except Exception:
        logger.exception("job=%s Claude API call failed", job_id)
        return None

    decision = _parse_ai_response(raw, job_id)
    if decision:
        logger.info("job=%s Claude verdict: phishing=%s score=%s",
                     job_id, decision.get("phishing"), decision.get("phishing_score"))
    return decision


# ---------------------------------------------------------------------------
# Backend: Ollama (local LLM)
# ---------------------------------------------------------------------------
def ask_ollama(prompt: str, job_id: str, model: str | None = None) -> dict | None:
    """Send prompt to a local Ollama instance. Returns parsed decision or None."""
    model = model or OLLAMA_MODEL
    logger.info("job=%s sending prompt to Ollama (%s @ %s)", job_id, model, OLLAMA_HOST)

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "format": "json",
        "stream": False,
    }

    try:
        resp = requests.post(
            f"{OLLAMA_HOST}/api/chat",
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        raw = resp.json().get("message", {}).get("content", "")
    except requests.RequestException:
        logger.exception("job=%s Ollama API call failed", job_id)
        return None

    if not raw:
        logger.error("job=%s Ollama returned empty response", job_id)
        return None

    decision = _parse_ai_response(raw, job_id)
    if decision:
        logger.info("job=%s Ollama verdict: phishing=%s score=%s",
                     job_id, decision.get("phishing"), decision.get("phishing_score"))
    return decision


# ---------------------------------------------------------------------------
# Backend router
# ---------------------------------------------------------------------------
def resolve_backend(data: dict) -> tuple[str, str | None]:
    """
    Determine which backend to use for this job.

    Priority:
      1. Job-level ai_model field – if it starts with "claude" -> claude backend
      2. Global AI_BACKEND env var

    Returns (backend_name, model_override).
    """
    job_model = data.get("ai_model", "")

    if isinstance(job_model, str) and job_model.lower().startswith("claude"):
        return "claude", job_model

    if AI_BACKEND == "claude":
        return "claude", None

    return "ollama", job_model if job_model else None


def ask_ai(prompt: str, job_id: str, data: dict) -> tuple[dict | None, str]:
    """
    Route the prompt to the correct backend.
    Returns (decision, backend_name).
    """
    backend, model_override = resolve_backend(data)

    if backend == "claude":
        decision = ask_claude(prompt, job_id, model=model_override)
    else:
        decision = ask_ollama(prompt, job_id, model=model_override)

    return decision, backend


# ---------------------------------------------------------------------------
# Discord notification
# ---------------------------------------------------------------------------
def notify_discord(data: dict, decision: dict | None, job_id: str, backend: str) -> bool:
    """Post the AI verdict to a Discord webhook. Returns True on success."""
    if not DISCORD_WEBHOOK_URL:
        logger.debug("job=%s no Discord webhook configured – skipping", job_id)
        return False

    _, final_url = _extract_redirect_urls(data)
    phishing = decision.get("phishing", "unknown") if decision else "error"
    score = decision.get("phishing_score", "N/A") if decision else "N/A"
    brand = decision.get("brands", "N/A") if decision else "N/A"
    reasoning = decision.get("reasoning", "No reasoning available") if decision else "Analysis failed"

    if phishing is True:
        color = 0xFF0000
        verdict = "PHISHING"
    elif phishing is False:
        color = 0x00FF00
        verdict = "LEGITIMATE"
    else:
        color = 0xFFFF00
        verdict = "UNKNOWN"

    payload = {
        "embeds": [
            {
                "title": f"phishGPT Verdict: {verdict}",
                "color": color,
                "fields": [
                    {"name": "URL", "value": final_url, "inline": False},
                    {"name": "Phishing Score", "value": str(score), "inline": True},
                    {"name": "Brand Detected", "value": str(brand), "inline": True},
                    {"name": "AI Backend", "value": backend, "inline": True},
                    {"name": "Job ID", "value": job_id, "inline": False},
                    {"name": "Reasoning", "value": reasoning[:1024], "inline": False},
                ],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ]
    }

    try:
        resp = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10)
        if resp.status_code in (200, 204):
            logger.info("job=%s verdict sent to Discord", job_id)
            return True
        logger.warning("job=%s Discord webhook returned %d: %s", job_id, resp.status_code, resp.text[:200])
        return False
    except Exception:
        logger.exception("job=%s failed to send Discord notification", job_id)
        return False


# ---------------------------------------------------------------------------
# Job processor
# ---------------------------------------------------------------------------
def process_job(data: dict) -> None:
    job_id: str = data["_id"]
    _, final_url = _extract_redirect_urls(data)

    logger.info("job=%s starting AI analysis for %s", job_id, final_url)
    set_job_status(job_id, "In Progress")

    prompt = create_prompt(data)
    decision, backend = ask_ai(prompt, job_id, data)

    save_results(job_id, decision, backend)
    notify_discord(data, decision, job_id, backend)

    logger.info("job=%s AI prompt job complete (backend=%s)", job_id, backend)


# ---------------------------------------------------------------------------
# Queue poller
# ---------------------------------------------------------------------------
def poll_queue() -> None:
    try:
        resp = requests.get(f"{BASE_APP}/phishGPT_queue", timeout=10)
    except requests.RequestException:
        logger.error("Failed to reach queue API at %s", BASE_APP, exc_info=True)
        return

    if resp.status_code != 200:
        logger.error("Queue API returned status %d", resp.status_code)
        return

    data = resp.json()
    if not data:
        logger.debug("No prompt jobs in queue")
        return

    try:
        process_job(data)
    except Exception:
        job_id = data.get("_id", "unknown")
        logger.exception("job=%s unhandled error during AI prompt processing", job_id)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info(
        "AI prompt worker starting – backend=%s polling every %ds",
        AI_BACKEND, POLL_INTERVAL,
    )
    while True:
        poll_queue()
        time.sleep(POLL_INTERVAL)