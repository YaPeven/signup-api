from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from base64 import b64decode
import re

app = Flask(__name__)
users = {}

def authenticate_basic():
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Basic "):
        return None, None
    try:
        encoded = auth.split(" ")[1]
        decoded = b64decode(encoded).decode("utf-8")
        user_id, password = decoded.split(":", 1)
        user = users.get(user_id)
        if user and check_password_hash(user["password"], password):
            return user_id, user
        return user_id, None
    except Exception:
        return None, None

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    user_id = data.get("user_id", "")
    password = data.get("password", "")
    if not re.fullmatch(r"[a-zA-Z0-9]{6,20}", user_id) or not re.fullmatch(r"[ -~]{8,20}", password):
        return jsonify({"message": "Account creation failed", "cause": "Required user_id and password"}), 400
    if user_id in users:
        return jsonify({"message": "Account creation failed", "cause": "Already same user_id is used"}), 400
    users[user_id] = {
        "password": generate_password_hash(password),
        "nickname": user_id,
        "comment": ""
    }
    return jsonify({
        "message": "Account successfully created",
        "user": {
            "user_id": user_id,
            "nickname": user_id
        }
    }), 200

@app.route("/users/<user_id>", methods=["GET"])
def get_user(user_id):
    req_id, user = authenticate_basic()
    if not user:
        return jsonify({"message": "Authentication failed"}), 401
    if user_id not in users:
        return jsonify({"message": "No user found"}), 404
    user_info = users[user_id]
    return jsonify({
        "message": "User details by user_id",
        "user": {
            "user_id": user_id,
            "nickname": user_info.get("nickname", user_id),
            "comment": user_info.get("comment", "")
        }
    }), 200

@app.route("/users/<user_id>", methods=["PATCH"])
def update_user(user_id):
    req_id, user = authenticate_basic()
    if not user:
        return jsonify({"message": "Authentication failed"}), 401
    if req_id != user_id:
        return jsonify({"message": "No permission for update"}), 403
    if user_id not in users:
        return jsonify({"message": "No user found"}), 404

    data = request.get_json()
    nickname = data.get("nickname")
    comment = data.get("comment")

    if nickname is None and comment is None:
        return jsonify({"message": "User updation failed", "cause": "Required nickname or comment"}), 400
    if (nickname is not None and not re.fullmatch(r"[^\x00-\x1F\x7F]{0,30}", nickname)) or \
       (comment is not None and not re.fullmatch(r"[^\x00-\x1F\x7F]{0,100}", comment)):
        return jsonify({"message": "User updation failed", "cause": "Invalid nickname or comment"}), 400

    if "user_id" in data or "password" in data:
        return jsonify({"message": "User updation failed", "cause": "Not updatable user_id and password"}), 400

    if nickname is not None:
        users[user_id]["nickname"] = nickname or user_id
    if comment is not None:
        users[user_id]["comment"] = comment

    return jsonify({
        "message": "User successfully updated",
        "user": [{
            "nickname": users[user_id]["nickname"],
            "comment": users[user_id]["comment"]
        }]
    }), 200

@app.route("/close", methods=["POST"])
def close_account():
    user_id, user = authenticate_basic()
    if not user:
        return jsonify({"message": "Authentication failed"}), 401
    users.pop(user_id)
    return jsonify({"message": "Account and user successfully removed"}), 200

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=3000)


