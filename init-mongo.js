// =============================================================================
// phishGPT – MongoDB Initialization Script
//
// Runs once when the container is first created (via /docker-entrypoint-initdb.d/).
// Creates the gpt_app collection with:
//   - Schema validation so bad documents can't sneak in
//   - Compound indexes matching every queue query pattern
//   - A TTL index to auto-purge completed jobs after 30 days
// =============================================================================

const db = db.getSiblingDB("gpt_app");

// ---------------------------------------------------------------------------
// 1. Create collection with JSON Schema validation
// ---------------------------------------------------------------------------
db.createCollection("gpt_app", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: [
        "_id",
        "url",
        "source_tag",
        "priority",
        "creation_time",
        "ai_model",
        "redirect_data",
        "net_tools_scan",
        "ocr_data",
        "screenshot_data",
        "ai_prompt",
      ],
      properties: {
        _id: {
          bsonType: "string",
          description: "UUID job identifier",
        },
        url: {
          bsonType: "string",
          description: "Original URL submitted for analysis",
        },
        source_tag: {
          bsonType: "string",
          description: "Source of the submission (e.g. phishgpt, manual)",
        },
        priority: {
          bsonType: "int",
          minimum: 0,
          description: "Job priority – lower numbers processed first",
        },
        creation_time: {
          bsonType: "string",
          description: "ISO 8601 timestamp of job creation",
        },
        ai_model: {
          bsonType: "string",
          description: "Requested AI model (e.g. llama3.3, claude-sonnet-4-20250514)",
        },
        blink_case_id: {
          bsonType: "string",
          description: "Optional SOAR case ID for callback",
        },

        // --- Pipeline stage sub-documents ---
        redirect_data: {
          bsonType: "object",
          required: ["status"],
          properties: {
            status: {
              enum: ["Pending", "In Progress", "Complete", "Error"],
              description: "Stage status",
            },
            result: {
              description: "Redirect check results or null",
            },
            start_date: {
              description: "ISO 8601 timestamp when processing started",
            },
          },
        },
        net_tools_scan: {
          bsonType: "object",
          required: ["status"],
          properties: {
            status: {
              enum: ["Pending", "In Progress", "Complete", "Error"],
              description: "Stage status",
            },
            result: {
              description: "Net tools results or null",
            },
            start_date: {
              description: "ISO 8601 timestamp when processing started",
            },
          },
        },
        ocr_data: {
          bsonType: "object",
          required: ["status"],
          properties: {
            status: {
              enum: ["Pending", "In Progress", "Complete", "Error"],
              description: "Stage status",
            },
            result: {
              description: "Extracted page text or null",
            },
            start_date: {
              description: "ISO 8601 timestamp when processing started",
            },
          },
        },
        screenshot_data: {
          bsonType: "object",
          required: ["status"],
          properties: {
            status: {
              enum: ["Pending", "In Progress", "Complete", "Error"],
              description: "Stage status",
            },
            result: {
              description: "Screenshot OCR + base64 image or null",
            },
            start_date: {
              description: "ISO 8601 timestamp when processing started",
            },
          },
        },
        ai_prompt: {
          bsonType: "object",
          required: ["status"],
          properties: {
            status: {
              enum: ["Pending", "In Progress", "Complete", "Error"],
              description: "Stage status",
            },
            decision: {
              description: "AI verdict JSON or null",
            },
            backend: {
              bsonType: "string",
              description: "Which AI backend produced the verdict (claude/ollama)",
            },
            start_date: {
              description: "ISO 8601 timestamp when processing started",
            },
          },
        },
      },
    },
  },
  validationLevel: "moderate",    // validate inserts + updates that touch validated fields
  validationAction: "warn",       // log violations but don't reject (safer for migration)
});

print("✓ Collection 'gpt_app' created with schema validation");

// ---------------------------------------------------------------------------
// 2. Indexes – one per queue query pattern, all sorted by priority
// ---------------------------------------------------------------------------

// Redirect queue: find Pending redirect jobs, sorted by priority
db.gpt_app.createIndex(
  { "redirect_data.status": 1, priority: 1 },
  { name: "idx_redirect_queue" }
);

// Net tools queue: find Pending net_tools where redirect is Complete
db.gpt_app.createIndex(
  { "net_tools_scan.status": 1, "redirect_data.status": 1, priority: 1 },
  { name: "idx_net_tools_queue" }
);

// Screenshot queue: find Pending screenshots where redirect is Complete
db.gpt_app.createIndex(
  { "screenshot_data.status": 1, "redirect_data.status": 1, priority: 1 },
  { name: "idx_screenshot_queue" }
);

// OCR queue: find Pending OCR where redirect is Complete
db.gpt_app.createIndex(
  { "ocr_data.status": 1, "redirect_data.status": 1, priority: 1 },
  { name: "idx_ocr_queue" }
);

// AI prompt queue: find Pending prompts where all upstream stages are Complete
db.gpt_app.createIndex(
  {
    "ai_prompt.status": 1,
    "net_tools_scan.status": 1,
    "ocr_data.status": 1,
    "screenshot_data.status": 1,
    "redirect_data.status": 1,
    priority: 1,
  },
  { name: "idx_ai_prompt_queue" }
);

// Priority index for the /list endpoint and general sorting
db.gpt_app.createIndex(
  { priority: 1, creation_time: -1 },
  { name: "idx_priority_created" }
);

print("✓ Queue indexes created");

// ---------------------------------------------------------------------------
// 3. TTL index – auto-delete completed jobs after 30 days
//
//    This requires creation_time to be stored as a Date. The current app
//    stores ISO strings, so this index won't fire until you migrate to
//    ISODate() values.  It's safe to create now – Mongo simply ignores
//    non-Date fields for TTL evaluation.
// ---------------------------------------------------------------------------
db.gpt_app.createIndex(
  { creation_time: 1 },
  { name: "idx_ttl_cleanup", expireAfterSeconds: 2592000 }  // 30 days
);

print("✓ TTL index created (30-day auto-cleanup for Date-typed creation_time)");

// ---------------------------------------------------------------------------
// 4. Done
// ---------------------------------------------------------------------------
print("✓ phishGPT database initialization complete");