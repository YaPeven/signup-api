from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from base64 import b64decode

app = Flask(__name__)
users = {}

def authenticate_basic():
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Basic "):
        return None, None
    try:
        encoded = auth[6:]
        decoded = b64decode(encoded).decode()
        user_id, password = decoded.split(":", 1)
        user = users.get(user_id)
        if user and check_password_hash(user["password"], password):
            return user_id, user_id
        return user_id, None
    except Exception:
        return None, None

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    user_id = data.get("user_id", "")
    password = data.get("password", "")

    if not user_id or not password:
        return jsonify({
            "message": "Account creation failed",
            "cause": "Required user_id and password"
        }), 400
    if len(user_id) < 6 or len(user_id) > 20 or not user_id.isalnum():
        return jsonify({
            "message": "Account creation failed",
            "cause": "Input length is incorrect"
        }), 400
    if len(password) < 8 or len(password) > 20 or not all(33 <= ord(c) <= 126 for c in password):
        return jsonify({
            "message": "Account creation failed",
            "cause": "Incorrect character pattern"
        }), 400
    if user_id in users:
        return jsonify({
            "message": "Account creation failed",
            "cause": "Already same user_id is used"
        }), 400

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
    target_id, authed_id = authenticate_basic()
    if authed_id is None:
        return jsonify({"message": "Authentication failed"}), 401
    if user_id not in users:
        return jsonify({"message": "No user found"}), 404
    user = users[user_id]
    response = {
        "message": "User details by user_id",
        "user": {
            "user_id": user_id,
            "nickname": user.get("nickname", user_id)
        }
    }
    if user.get("comment"):
        response["user"]["comment"] = user["comment"]
    return jsonify(response), 200

@app.route("/users/<user_id>", methods=["PATCH"])
def update_user(user_id):
    target_id, authed_id = authenticate_basic()
    if authed_id is None:
        return jsonify({"message": "Authentication failed"}), 401
    if authed_id != user_id:
        return jsonify({"message": "No permission for update"}), 403
    if user_id not in users:
        return jsonify({"message": "No user found"}), 404

    data = request.get_json()
    nickname = data.get("nickname")
    comment = data.get("comment")

    if nickname is None and comment is None:
        return jsonify({
            "message": "User updation failed",
            "cause": "Required nickname or comment"
        }), 400

    if nickname is not None:
        if nickname == "":
            users[user_id]["nickname"] = user_id
        elif len(nickname) > 30 or any(ord(c) < 32 for c in nickname):
            return jsonify({
                "message": "User updation failed",
                "cause": "Invalid nickname or comment"
            }), 400
        else:
            users[user_id]["nickname"] = nickname

    if comment is not None:
        if comment == "":
            users[user_id]["comment"] = ""
        elif len(comment) > 100 or any(ord(c) < 32 for c in comment):
            return jsonify({
                "message": "User updation failed",
                "cause": "Invalid nickname or comment"
            }), 400
        else:
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
    target_id, authed_id = authenticate_basic()
    if authed_id is None:
        return jsonify({"message": "Authentication failed"}), 401
    if authed_id not in users:
        return jsonify({"message": "No user found"}), 404

    del users[authed_id]
    return jsonify({
        "message": "Account and user successfully removed"
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)


