from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from base64 import b64decode
import re

app = Flask(__name__)
users = {}

def authenticate():
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Basic "):
        return None
    try:
        encoded = auth[6:]
        decoded = b64decode(encoded).decode()
        user_id, password = decoded.split(":", 1)
        user = users.get(user_id)
        if user and check_password_hash(user["password"], password):
            return user_id
    except Exception:
        pass
    return None

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    user_id = data.get("user_id")
    password = data.get("password")

    if not user_id or not password:
        return jsonify({"message": "Account creation failed", "cause": "Required user_id and password"}), 400

    if not re.fullmatch(r"[0-9A-Za-z]{6,20}", user_id):
        return jsonify({"message": "Account creation failed", "cause": "Incorrect character pattern"}), 400

    if not re.fullmatch(r"[!-~]{8,20}", password):  # ASCII printable characters
        return jsonify({"message": "Account creation failed", "cause": "Incorrect character pattern"}), 400

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
    })

@app.route("/users/<user_id>", methods=["GET"])
def get_user(user_id):
    auth_id = authenticate()
    if not auth_id:
        return jsonify({"message": "Authentication failed"}), 401
    if user_id not in users:
        return jsonify({"message": "No user found"}), 404

    user = users[user_id]
    response = {
        "message": "User details by user_id",
        "user": {
            "user_id": user_id
        }
    }
    if user["nickname"] and user["nickname"] != user_id:
        response["user"]["nickname"] = user["nickname"]
    else:
        response["user"]["nickname"] = user_id
    if user["comment"]:
        response["user"]["comment"] = user["comment"]
    return jsonify(response)

@app.route("/users/<user_id>", methods=["PATCH"])
def update_user(user_id):
    auth_id = authenticate()
    if not auth_id:
        return jsonify({"message": "Authentication failed"}), 401
    if auth_id != user_id:
        return jsonify({"message": "No permission for update"}), 403
    if user_id not in users:
        return jsonify({"message": "No user found"}), 404

    data = request.json or {}
    nickname = data.get("nickname")
    comment = data.get("comment")

    if nickname is None and comment is None:
        return jsonify({"message": "User updation failed", "cause": "Required nickname or comment"}), 400

    if nickname is not None:
        if not isinstance(nickname, str) or len(nickname) > 30:
            return jsonify({"message": "User updation failed", "cause": "Invalid nickname or comment"}), 400
        users[user_id]["nickname"] = nickname if nickname else user_id

    if comment is not None:
        if not isinstance(comment, str) or len(comment) > 100:
            return jsonify({"message": "User updation failed", "cause": "Invalid nickname or comment"}), 400
        users[user_id]["comment"] = comment if comment else ""

    return jsonify({
        "message": "User successfully updated",
        "user": [
            {
                "nickname": users[user_id]["nickname"],
                "comment": users[user_id]["comment"]
            }
        ]
    })

@app.route("/close", methods=["POST"])
def close_account():
    user_id = authenticate()
    if not user_id:
        return jsonify({"message": "Authentication failed"}), 401
    users.pop(user_id, None)
    return jsonify({"message": "Account and user successfully removed"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

