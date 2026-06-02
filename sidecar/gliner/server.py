import sys
import json
import logging
from flask import Flask, request, jsonify

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gliner-sidecar")

app = Flask(__name__)
model = None

ENTITY_LABELS = [
    "PERSON", "EMAIL", "PHONE", "ADDRESS", "SSN",
    "CREDIT_CARD", "DATE_OF_BIRTH", "MEDICAL_RECORD",
    "FINANCIAL_ACCOUNT", "PASSPORT", "DRIVER_LICENSE",
    "IP_ADDRESS", "ORGANIZATION", "USERNAME",
    "LOCATION", "IBAN", "BANK_ACCOUNT",
    "INSURANCE_NUMBER", "LICENSE_PLATE",
    "NATIONAL_ID", "TAX_ID", "PASSWORD",
]

def load_model():
    global model
    logger.info("Loading GLiNER model...")
    from gliner import GLiNER
    model = GLiNER.from_pretrained("urchade/gliner_multi_pii-v1")
    logger.info("GLiNER model loaded")

@app.route("/health", methods=["GET"])
def health():
    if model is None:
        return jsonify({"status": "loading"}), 503
    return jsonify({"status": "ready"})

@app.route("/detect", methods=["POST"])
def detect():
    if model is None:
        return jsonify({"entities": []}), 200

    data = request.get_json()
    text = data.get("text", "")
    if not text:
        return jsonify({"entities": []})

    entities = model.predict_entities(text, ENTITY_LABELS, threshold=0.4)

    results = []
    for ent in entities:
        results.append({
            "text": ent["text"],
            "label": ent["label"],
            "start": ent["start"],
            "end": ent["end"],
            "score": round(ent["score"], 4),
        })

    return jsonify({"entities": results})

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765

    import threading
    threading.Thread(target=load_model, daemon=True).start()

    from waitress import serve
    logger.info(f"Starting GLiNER sidecar on port {port}")
    serve(app, host="127.0.0.1", port=port)
