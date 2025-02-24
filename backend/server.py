from flask import Flask, request, jsonify
import os
import uuid
import datetime
import traceback
from flask_cors import CORS
from pymongo import MongoClient
from scanners.pdfScanner import PDFScanner
from scanners.docxScanner import DOCXScanner
from scanners.pescanner import PEScanner

app = Flask(__name__)
CORS(app)

# Get absolute path for the current directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Ensure the upload folder exists

ALLOWED_EXTENSIONS = {'pdf', 'docx','exe'}

# Securely fetch MongoDB URL from environment
MONGO_URL = "mongodb+srv://lolplaynoob:rZWMG4CB11amr1wH@yara.qs2mu.mongodb.net/?retryWrites=true&w=majority&appName=YARA"
client = MongoClient(MONGO_URL)
db = client["scan_database"]
history_collection = db.history  # Correct collection reference

# Load scanner rules with absolute paths
pdf_scanner = PDFScanner(os.path.join(BASE_DIR, "yarrules/pdf_rules.yar"))
docx_scanner = DOCXScanner(os.path.join(BASE_DIR, "yarrules/docx_rules.yar"))
pe_scanner = PEScanner(os.path.join(BASE_DIR, "yarrules/exe_rules.yar"))

def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def format_file_size(size_bytes: int) -> str:
    """Convert file size to human-readable format"""
    for unit in ['bytes', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"

@app.route("/scan", methods=["POST"])
def scan_file():
    """Endpoint to scan uploaded PDF and DOCX files"""
    if "file" not in request.files or "userid" not in request.form:
        return jsonify({"error": "File and User ID required"}), 400

    file = request.files["file"]
    userid = request.form["userid"]

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Only PDF, DOCX, EXE files are allowed"}), 400

    filename = file.filename
    file_extension = filename.rsplit('.', 1)[1].lower()
    
    file.seek(0)  # Reset file pointer before reading
    filesize = len(file.read())
    file.seek(0)  # Reset file pointer before saving

    unique_filename = f"{uuid.uuid4()}_{filename}"
    filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
    file.save(filepath)

    timestamp = datetime.datetime.now().isoformat()

    scan_results = {}

    try:
        # Scan the file
        if file_extension == "pdf":
            scan_results = pdf_scanner.scan_pdf(filepath)
        elif file_extension == "docx":
            scan_results = docx_scanner.generate_report(filepath)
        elif file_extension == "exe":
            scan_results = pe_scanner.scan_file(filepath)
        else:
            raise Exception("Unsupported file type")

        scan_record = {
            **scan_results,
            "filename": filename,
            "filesize": filesize,
            "formatted_size": format_file_size(filesize),
            "timestamp": timestamp,
            "file_type": file_extension
        }

        # Save scan history
        history_collection.update_one(
            {"userid": userid},
            {"$push": {"history": scan_record}},
            upsert=True
        )

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

    finally:
        # Ensure file deletion even if an error occurs
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
                print(f"Deleted file: {filepath}")
            except Exception as e:
                print(f"Failed to delete {filepath}: {e}")

    return jsonify({"scan_result": scan_record})


@app.route("/history", methods=["GET"])
def get_history():
    """Endpoint to retrieve scan history"""
    userid = request.args.get("userid")
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 5))

    if not userid:
        return jsonify({"error": "User ID required"}), 400

    try:
        user_history = history_collection.find_one(
            {"userid": userid},
            {"_id": 0, "history": 1}
        )

        if not user_history or "history" not in user_history:
            return jsonify({"history": []})

        history = sorted(
            user_history["history"],
            key=lambda x: x.get("timestamp", ""),
            reverse=True
        )

        start, end = (page - 1) * limit, page * limit
        paginated_history = history[start:end]

        return jsonify({
            "history": paginated_history,
            "total": len(history),
            "pages": (len(history) + limit - 1) // limit
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/stats", methods=["GET"])
def get_stats():
    """Endpoint to get scanning statistics"""
    userid = request.args.get("userid")

    if not userid:
        return jsonify({"error": "User ID required"}), 400

    try:
        user_history = history_collection.find_one(
            {"userid": userid},
            {"_id": 0, "history": 1}
        )

        if not user_history or "history" not in user_history:
            return jsonify({"stats": {
                "total_scans": 0,
                "clean_files": 0,
                "infected_files": 0,
                "threat_levels": {"low": 0, "medium": 0, "high": 0},
                "file_types": {"pdf": 0, "exe": 0, "docx": 0}
            }}), 200

        history = user_history["history"]

        stats = {
            "total_scans": len(history),
            "clean_files": sum(1 for scan in history if scan.get("threat_level") == "low"),
            "infected_files": sum(1 for scan in history if scan.get("threat_level") != "low"),
            "threat_levels": {
                "low": sum(1 for scan in history if scan.get("threat_level") == "low"),
                "medium": sum(1 for scan in history if scan.get("threat_level") == "medium"),
                "high": sum(1 for scan in history if scan.get("threat_level") == "high")
            },
            "file_types": {
                "pdf": sum(1 for scan in history if scan["filename"].lower().endswith(".pdf")),
                "exe": sum(1 for scan in history if scan["filename"].lower().endswith(".exe")),
                "docx": sum(1 for scan in history if scan["filename"].lower().endswith(".docx"))
            }
        }

        return jsonify({"stats": stats}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
