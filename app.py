from flask import Flask, render_template, Response, jsonify
import json
import events as ev

app = Flask(__name__)

_devices = {}

def set_devices(d):
    global _devices
    _devices = d

@app.route("/devices")
def devices():
    return jsonify([
        {"mac": mac, "name": info["name"], "device": info["device"], "ip": info["ip"]}
        for mac, info in _devices.items()
    ])

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/history")
def history():
    return jsonify(list(ev.history))

@app.route("/stream")
def stream():
    q = ev.subscribe()
    def generate():
        try:
            while True:
                event = q.get()
                yield f"data: {json.dumps(event)}\n\n"
        finally:
            ev.unsubscribe(q)
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

def run():
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
