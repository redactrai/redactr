import sys
import json
import logging
import time
from flask import Flask, request, jsonify

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("opf-sidecar")

app = Flask(__name__)
model = None


def load_model():
    global model
    logger.info("Loading OPF model...")
    from opf._api import OPF
    model = OPF(device="cpu", output_text_only=False)
    # Warm up with a short text to trigger lazy init
    model.redact("warmup")
    logger.info("OPF model loaded")


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

    result = model.redact(text)

    entities = []
    for span in result.detected_spans:
        entities.append({
            "text": span.text,
            "label": span.label.upper(),
            "start": span.start,
            "end": span.end,
            "score": 0.95,
        })

    return jsonify({"entities": entities})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8766

    import threading
    threading.Thread(target=load_model, daemon=True).start()

    from waitress import serve
    logger.info(f"Starting OPF sidecar on port {port}")
    serve(app, host="127.0.0.1", port=port)
