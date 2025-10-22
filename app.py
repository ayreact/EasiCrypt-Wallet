import os
from flask import Flask, request, jsonify
from dotenv import load_dotenv

load_dotenv()

from ussd_flow import handle_ussd_request
from models import User

app = Flask(__name__)

@app.route('/ussd', methods=['POST'])
def ussd_callback():
    session_id = request.form.get('sessionId')
    phone_number = request.form.get('phoneNumber')
    text = request.form.get('text')

    if not all([session_id, phone_number]):
        return "END Invalid USSD request.", 400

    response = handle_ussd_request(session_id, phone_number, text)

    return response, 200, {'Content-Type': 'text/plain'}

# Dummny Endpoint made for cronjob
@app.route('/')
def health_check():
    try:
        user_count = User.objects.count()
        return jsonify({"status": "EasiCrypt API is running", "db_connected": True, "user_count": user_count}), 200
    except Exception as e:
        return jsonify({"status": "EasiCrypt API is running", "db_connected": False, "error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)