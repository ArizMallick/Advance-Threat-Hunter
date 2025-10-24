import uuid
import time
import threading
from typing import Dict
import re
import tempfile
import os

from flask import Flask, request, jsonify, Response, send_from_directory
from flask_cors import CORS
import psutil

# Initialize Flask
app = Flask(__name__, static_folder='static', template_folder='.')
CORS(app)

# Suspicious keywords and regexes
SUSPICIOUS_KEYWORDS = [
    "hack", "keylogger", "trojan", "virus", "spyware", "malware", "ransomware",
    "unauthorized", "failed password", "invalid user", "sudo", "passwd",
    "reverse shell", "nc -e", "curl http", "wget http", "base64 -d"
]

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
CMD_RE = re.compile(r"\b(nc\s+-e|bash\s+-i|sh\s+-i|python\s+-c|perl\s+-e|curl\s+http|wget\s+http)\b", re.IGNORECASE)

# In-memory session store for scan logs
sessions: Dict[str, Dict] = {}

# -------------------------------------------
# 🔹 Function: Scan Uploaded Log Files
# -------------------------------------------
def scan_log_lines(lines):
    results = []
    summary = {"keyword_matches": 0, "ip_matches": 0, "base64_matches": 0, "cmd_matches": 0}

    for i, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n\r")
        matches = []
        low = line.lower()

        for kw in SUSPICIOUS_KEYWORDS:
            if kw in low:
                matches.append({"type": "keyword", "value": kw})
                summary["keyword_matches"] += 1

        for m in IPV4_RE.findall(line):
            matches.append({"type": "ip", "value": m})
            summary["ip_matches"] += 1

        base64_m = BASE64_RE.search(line)
        if base64_m:
            matches.append({"type": "base64", "value": base64_m.group(0)})
            summary["base64_matches"] += 1

        cmd_m = CMD_RE.search(line)
        if cmd_m:
            matches.append({"type": "cmd", "value": cmd_m.group(0)})
            summary["cmd_matches"] += 1

        if matches:
            results.append({"line_no": i, "text": line, "matches": matches})

    return results, summary

# -------------------------------------------
# 🔹 Background System Scanner
# -------------------------------------------
def scan_system(session_id: str):
    def push(message: str):
        sessions[session_id]["log"].append(message)

    push("🔍 Starting system scan...")
    push(f"📊 Session ID: {session_id}")
    time.sleep(0.5)

    threats_found = False
    suspicious_count = 0
    process_count = 0

    try:
        for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'cpu_percent']):
            try:
                process_count += 1
                name = proc.info['name'] or ""
                pid = proc.info.get('pid', 'N/A')
                memory = proc.info.get('memory_percent') or 0.0

                if any(k in name.lower() for k in SUSPICIOUS_KEYWORDS):
                    push(f"⚠️ ALERT: Suspicious Process: {name} | PID: {pid}")
                    suspicious_count += 1
                    threats_found = True

                if memory > 30.0:
                    push(f"⚠️ WARNING: High Memory Usage: {name} | {memory:.2f}% | PID: {pid}")
                    threats_found = True

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        push(f"📈 Total Processes Scanned: {process_count}")
        if suspicious_count > 0:
            push(f"🚨 Suspicious Processes Found: {suspicious_count}")

        mem = psutil.virtual_memory()
        push(f"💾 Memory Usage: {mem.percent}%")
        if mem.percent > 80:
            push("⚠️ WARNING: High Memory Usage")

        cpu = psutil.cpu_percent(interval=1)
        push(f"⚡ CPU Usage: {cpu}%")
        if cpu > 80:
            push("⚠️ WARNING: High CPU Usage")

        disk = psutil.disk_usage('/')
        push(f"💿 Disk Usage: {disk.percent}%")
        if disk.percent > 90:
            push("⚠️ WARNING: Low Disk Space")

    except Exception as e:
        push(f"❌ Error occurred: {str(e)}")

    push("=" * 50)
    push("✅ Scan Complete - No threats found." if not threats_found else "🚨 Threats detected. Review logs above.")
    push(f"⏱️ Finished at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    sessions[session_id]["done"] = True

# -------------------------------------------
# 🔹 API Routes
# -------------------------------------------

@app.route('/')
def home():
    return send_from_directory('.', 'static/index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    session_id = str(uuid.uuid4())
    sessions[session_id] = {"log": [], "done": False}

    thread = threading.Thread(target=scan_system, args=(session_id,), daemon=True)
    thread.start()

    return jsonify({"session": session_id, "status": "started"})

@app.route('/api/scan/stream')
def stream_logs():
    session = request.args.get('session', '')
    if session not in sessions:
        return Response('data: Invalid session\n\n', mimetype='text/event-stream')

    def event_stream():
        index = 0
        while not sessions[session]["done"] or index < len(sessions[session]["log"]):
            while index < len(sessions[session]["log"]):
                yield f"data: {sessions[session]['log'][index]}\n\n"
                index += 1
            time.sleep(0.3)
        yield "event: done\ndata: Scan finished.\n\n"

    return Response(event_stream(), mimetype='text/event-stream')

@app.route('/api/scan/upload', methods=['POST'])
def upload_and_scan():
    if 'file' not in request.files or request.files['file'].filename == '':
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            file.save(tmp.name)
        with open(tmp.name, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        results, summary = scan_log_lines(lines)
        return jsonify({
            "filename": file.filename,
            "matches": results,
            "summary": summary,
            "total_lines": len(lines)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/health')
def health_check():
    return jsonify({
        "status": "healthy",
        "active_sessions": len(sessions),
        "time": time.strftime('%Y-%m-%d %H:%M:%S')
    })

# -------------------------------------------
# Run Server
# -------------------------------------------
if __name__ == '__main__':
    print("🛡️ Advanced Threat Hunter Backend Running on http://0.0.0.0:4000")
    app.run(host='0.0.0.0', port=4000, debug=False, threaded=True)
