import os
import json
import base64
import time
import logging
import requests
from flask import Flask, request, Response, jsonify

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_app() -> Flask:
    app = Flask(__name__)
    BACKEND_URL = os.environ.get("URL_BASE_BACKEND_SERVICES", "http://localhost:3000")

    def validate_jwt(auth_header):
        if not auth_header or not auth_header.startswith("Bearer "):
            return False, "Missing or invalid Authorization header"
        token = auth_header.split(" ")[1]
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return False, "Invalid JWT format"
            
            payload_b64 = parts[1]
            payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64).decode("utf-8")
            payload = json.loads(payload_json)
            
            # Check sub
            valid_subs = ["starlord", "gamora", "drax", "rocket", "groot"]
            if payload.get("sub") not in valid_subs:
                return False, "Invalid sub"
                
            # Check exp
            exp = payload.get("exp")
            if not exp or int(time.time()) >= int(exp):
                return False, "Token expired"
                
            # Check iss
            if payload.get("iss") != "cmu.edu":
                return False, "Invalid iss"
                
            return True, None
        except Exception as e:
            return False, str(e)

    @app.route('/status')
    def status():
        return {"status": "ok", "service": "web-bff"}, 200

    @app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    @app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    def proxy(path):
        # 1. Check X-Client-Type
        if not request.headers.get("X-Client-Type"):
            return jsonify({"error": "Missing X-Client-Type header"}), 400

        # 2. Check JWT
        auth_header = request.headers.get("Authorization")
        is_valid, err_msg = validate_jwt(auth_header)
        if not is_valid:
            return jsonify({"error": err_msg}), 401

        # 3. Forward request
        url = f"{BACKEND_URL}/{path}"
        headers = {key: value for key, value in request.headers if key.lower() != 'host'}
        
        try:
            resp = requests.request(
                method=request.method,
                url=url,
                headers=headers,
                data=request.get_data(),
                params=request.args,
                allow_redirects=False,
                timeout=10
            )
            
            excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
            resp_headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded_headers]
            return Response(resp.content, resp.status_code, resp_headers)
        except requests.exceptions.RequestException as e:
            logger.error(f"Error proxying request: {e}")
            return jsonify({"error": "Backend service unavailable"}), 502

    return app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
