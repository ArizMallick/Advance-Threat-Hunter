import uuid
import time
import threading
from typing import Dict
import re
import tempfile
import os
from datetime import datetime

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
    "reverse shell", "nc -e", "curl http", "wget http", "base64 -d",
    "exploit", "payload", "backdoor", "rootkit", "botnet"
]

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
CMD_RE = re.compile(r"\b(nc\s+-e|bash\s+-i|sh\s+-i|python\s+-c|perl\s+-e|curl\s+http|wget\s+http|powershell|cmd\.exe)\b", re.IGNORECASE)

# In-memory session store for scan logs
sessions: Dict[str, Dict] = {}

# Global stats
stats = {
    "total_scans": 0,
    "total_threats_found": 0,
    "total_files_analyzed": 0,
    "uptime_start": time.time()
}

# -------------------------------------------
# 🔹 Function: Scan Uploaded Log Files
# -------------------------------------------
def scan_log_lines(lines):
    """Scan log lines for suspicious patterns"""
    results = []
    summary = {
        "keyword_matches": 0, 
        "ip_matches": 0, 
        "base64_matches": 0, 
        "cmd_matches": 0
    }

    for i, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n\r")
        matches = []
        low = line.lower()

        # Check for suspicious keywords
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in low:
                matches.append({"type": "keyword", "value": kw})
                summary["keyword_matches"] += 1

        # Check for IP addresses
        for m in IPV4_RE.findall(line):
            matches.append({"type": "ip", "value": m})
            summary["ip_matches"] += 1

        # Check for Base64 strings
        base64_m = BASE64_RE.search(line)
        if base64_m:
            matches.append({"type": "base64", "value": base64_m.group(0)[:50] + "..."})
            summary["base64_matches"] += 1

        # Check for suspicious commands
        cmd_m = CMD_RE.search(line)
        if cmd_m:
            matches.append({"type": "cmd", "value": cmd_m.group(0)})
            summary["cmd_matches"] += 1

        if matches:
            results.append({
                "line_no": i, 
                "text": line[:200],  # Limit line length
                "matches": matches
            })

    return results, summary

# -------------------------------------------
# 🔹 Background System Scanner
# -------------------------------------------
def scan_system(session_id: str):
    """Background system scanning function"""
    def push(message: str):
        sessions[session_id]["log"].append(message)

    try:
        push("=" * 80)
        push("🔍 ADVANCED THREAT HUNTER - SYSTEM SCAN INITIATED")
        push("=" * 80)
        push(f"📋 Session ID: {session_id}")
        push(f"⏰ Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        push("=" * 80)
        time.sleep(0.5)

        threats_found = False
        suspicious_count = 0
        process_count = 0
        high_memory_processes = []
        high_cpu_processes = []

        # Scan processes
        push("\n🔎 Scanning running processes...")
        push("-" * 80)
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'cpu_percent', 'username']):
                try:
                    process_count += 1
                    name = proc.info.get('name', 'Unknown')
                    pid = proc.info.get('pid', 'N/A')
                    memory = proc.info.get('memory_percent', 0.0) or 0.0
                    cpu = proc.info.get('cpu_percent', 0.0) or 0.0
                    username = proc.info.get('username', 'Unknown')

                    # Check for suspicious process names
                    if any(k in name.lower() for k in SUSPICIOUS_KEYWORDS):
                        push(f"⚠️  ALERT: Suspicious Process Detected!")
                        push(f"   └─ Name: {name}")
                        push(f"   └─ PID: {pid}")
                        push(f"   └─ User: {username}")
                        push(f"   └─ Memory: {memory:.2f}%")
                        suspicious_count += 1
                        threats_found = True

                    # Track high memory usage
                    if memory > 30.0:
                        high_memory_processes.append({
                            'name': name, 
                            'pid': pid, 
                            'memory': memory
                        })

                    # Track high CPU usage
                    if cpu > 50.0:
                        high_cpu_processes.append({
                            'name': name, 
                            'pid': pid, 
                            'cpu': cpu
                        })

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            push(f"\n📊 Process Scan Complete")
            push(f"   └─ Total Processes Scanned: {process_count}")
            push(f"   └─ Suspicious Processes: {suspicious_count}")
            
            if suspicious_count > 0:
                sessions[session_id]["threats"] += suspicious_count

        except Exception as e:
            push(f"❌ Error scanning processes: {str(e)}")

        # High memory processes
        if high_memory_processes:
            push("\n⚠️  HIGH MEMORY USAGE DETECTED:")
            push("-" * 80)
            for proc in sorted(high_memory_processes, key=lambda x: x['memory'], reverse=True)[:5]:
                push(f"   • {proc['name']} (PID: {proc['pid']}) - {proc['memory']:.2f}% Memory")
                threats_found = True

        # High CPU processes
        if high_cpu_processes:
            push("\n⚠️  HIGH CPU USAGE DETECTED:")
            push("-" * 80)
            for proc in sorted(high_cpu_processes, key=lambda x: x['cpu'], reverse=True)[:5]:
                push(f"   • {proc['name']} (PID: {proc['pid']}) - {proc['cpu']:.2f}% CPU")
                threats_found = True

        # System metrics
        push("\n💾 SYSTEM RESOURCE ANALYSIS:")
        push("-" * 80)
        
        try:
            mem = psutil.virtual_memory()
            push(f"   • Memory Usage: {mem.percent}%")
            if mem.percent > 80:
                push(f"   └─ ⚠️  WARNING: Critical memory usage!")
                threats_found = True
            elif mem.percent > 60:
                push(f"   └─ ⚠️  CAUTION: High memory usage")

            cpu = psutil.cpu_percent(interval=1)
            push(f"   • CPU Usage: {cpu}%")
            if cpu > 80:
                push(f"   └─ ⚠️  WARNING: Critical CPU usage!")
                threats_found = True
            elif cpu > 60:
                push(f"   └─ ⚠️  CAUTION: High CPU usage")

            disk = psutil.disk_usage('/')
            push(f"   • Disk Usage: {disk.percent}%")
            if disk.percent > 90:
                push(f"   └─ ⚠️  WARNING: Critical disk space!")
                threats_found = True
            elif disk.percent > 80:
                push(f"   └─ ⚠️  CAUTION: Low disk space")

            # Network connections (count)
            net_connections = len(psutil.net_connections(kind='inet'))
            push(f"   • Active Network Connections: {net_connections}")
            if net_connections > 100:
                push(f"   └─ ⚠️  CAUTION: High number of connections")

        except Exception as e:
            push(f"❌ Error getting system metrics: {str(e)}")

        # Final summary
        push("\n" + "=" * 80)
        if threats_found:
            push("🚨 SCAN COMPLETE - THREATS DETECTED!")
            push("=" * 80)
            push("⚠️  Action Required: Review the alerts above")
            push("💡 Recommendation: Investigate suspicious processes and resource usage")
            sessions[session_id]["threats"] += 1
            stats["total_threats_found"] += 1
        else:
            push("✅ SCAN COMPLETE - NO THREATS DETECTED")
            push("=" * 80)
            push("🛡️  System Status: Secure")
            push("✓ No suspicious activity found")
            push("✓ Resource usage within normal limits")

        push(f"⏱️  Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        push("=" * 80)

    except Exception as e:
        push(f"\n❌ CRITICAL ERROR: {str(e)}")
        push("=" * 80)
    
    finally:
        sessions[session_id]["done"] = True
        stats["total_scans"] += 1

# -------------------------------------------
# 🔹 API Routes
# -------------------------------------------

@app.route('/')
def home():
    """Serve the main HTML page"""
    return send_from_directory('static', 'index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new system scan"""
    session_id = str(uuid.uuid4())
    sessions[session_id] = {
        "log": [], 
        "done": False, 
        "threats": 0,
        "start_time": time.time()
    }

    thread = threading.Thread(target=scan_system, args=(session_id,), daemon=True)
    thread.start()

    return jsonify({
        "session": session_id, 
        "status": "started",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/scan/stream')
def stream_logs():
    """Stream scan logs via Server-Sent Events"""
    session = request.args.get('session', '')
    
    if session not in sessions:
        return Response('data: {"error": "Invalid session"}\n\n', mimetype='text/event-stream')

    def event_stream():
        index = 0
        while not sessions[session]["done"] or index < len(sessions[session]["log"]):
            while index < len(sessions[session]["log"]):
                yield f"data: {sessions[session]['log'][index]}\n\n"
                index += 1
            time.sleep(0.3)
        
        # Send completion event
        yield "event: done\ndata: Scan finished successfully\n\n"

    return Response(event_stream(), mimetype='text/event-stream')

@app.route('/api/scan/upload', methods=['POST'])
def upload_and_scan():
    """Upload and scan a log file"""
    if 'file' not in request.files or request.files['file'].filename == '':
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    
    try:
        # Save to temporary file
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as tmp:
            file.save(tmp.name)
            tmp_path = tmp.name
        
        # Read and scan the file
        with open(tmp_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        
        # Clean up temp file
        os.unlink(tmp_path)
        
        # Scan the lines
        results, summary = scan_log_lines(lines)
        
        # Update stats
        stats["total_files_analyzed"] += 1
        if len(results) > 0:
            stats["total_threats_found"] += len(results)
        
        return jsonify({
            "success": True,
            "filename": file.filename,
            "matches": results,
            "summary": summary,
            "total_lines": len(lines),
            "timestamp": datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/scan/logs')
def get_scan_logs():
    """Get scan logs (polling fallback)"""
    session = request.args.get('session', '')
    
    if session not in sessions:
        return jsonify({"error": "Invalid session"}), 404
    
    return jsonify({
        "session": session,
        "lines": sessions[session]["log"],
        "done": sessions[session]["done"],
        "threats": sessions[session].get("threats", 0)
    })

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    uptime_seconds = int(time.time() - stats["uptime_start"])
    uptime_minutes = uptime_seconds // 60
    uptime_hours = uptime_minutes // 60
    
    return jsonify({
        "status": "healthy",
        "service": "Advanced Threat Hunter",
        "version": "2.0",
        "active_sessions": len([s for s in sessions.values() if not s["done"]]),
        "total_sessions": len(sessions),
        "stats": {
            "total_scans": stats["total_scans"],
            "total_threats_found": stats["total_threats_found"],
            "total_files_analyzed": stats["total_files_analyzed"]
        },
        "uptime": {
            "seconds": uptime_seconds,
            "formatted": f"{uptime_hours}h {uptime_minutes % 60}m {uptime_seconds % 60}s"
        },
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/stats')
def get_stats():
    """Get system statistics"""
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return jsonify({
            "cpu": {
                "percent": cpu_percent,
                "count": psutil.cpu_count()
            },
            "memory": {
                "total": memory.total,
                "available": memory.available,
                "percent": memory.percent,
                "used": memory.used
            },
            "disk": {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": disk.percent
            },
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/sessions')
def list_sessions():
    """List all scan sessions"""
    session_list = []
    for sid, data in sessions.items():
        session_list.append({
            "id": sid,
            "done": data["done"],
            "threats": data.get("threats", 0),
            "log_lines": len(data["log"]),
            "start_time": data.get("start_time", 0)
        })
    
    return jsonify({
        "sessions": session_list,
        "total": len(session_list)
    })

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    return jsonify({"error": "Internal server error"}), 500

# -------------------------------------------
# 🔹 Cleanup old sessions periodically
# -------------------------------------------
def cleanup_old_sessions():
    """Clean up sessions older than 1 hour"""
    while True:
        time.sleep(3600)  # Run every hour
        current_time = time.time()
        sessions_to_remove = []
        
        for sid, data in sessions.items():
            if data["done"] and (current_time - data.get("start_time", current_time)) > 3600:
                sessions_to_remove.append(sid)
        
        for sid in sessions_to_remove:
            del sessions[sid]
        
        if sessions_to_remove:
            print(f"🧹 Cleaned up {len(sessions_to_remove)} old sessions")

# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_old_sessions, daemon=True)
cleanup_thread.start()

# -------------------------------------------
# 🔹 Run Server
# -------------------------------------------
if __name__ == '__main__':
    print("=" * 80)
    print("🛡️  ADVANCED THREAT HUNTER - BACKEND SERVER")
    print("=" * 80)
    print("📡 Server: http://0.0.0.0:4000")
    print("🌐 Frontend: http://127.0.0.1:4000")
    print("📊 Health Check: http://127.0.0.1:4000/api/health")
    print("=" * 80)
    print("✅ Server starting...")
    print("⏳ Press CTRL+C to stop")
    print("=" * 80)
    
    app.run(host='0.0.0.0', port=4000, debug=False, threaded=True)