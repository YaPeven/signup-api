from flask import Flask, request, jsonify
from functools import wraps
import base64

app = Flask(__name__)
users = {}

def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Basic "):
            return jsonify({"message": "Authentication failed"}), 401
        try:
            encoded = auth.split(" ")[1]
            decoded = base64.b64decode(encoded).decode("utf-8")
            user_id, password = decoded.split(":")
        except Exception:
            return jsonify({"message": "Authentication failed"}), 401
        user = users.get(user_id)
        if user and user["password"] == password:
            request.user_id = user_id
            return f(*args, **kwargs)
        return jsonify({"message": "Authentication failed"}), 401
    return decorated_function

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    user_id = data.get("user_id", "")
    password = data.get("password", "")
    if not user_id or not password:
        return jsonify({"message": "Account creation failed", "cause": "Required user_id and password"}), 400
    if not (6 <= len(user_id) <= 20) or not user_id.isalnum():
        return jsonify({"message": "Account creation failed", "cause": "Input length is incorrect"}), 400
    if not (8 <= len(password) <= 20):
        return jsonify({"message": "Account creation failed", "cause": "Input length is incorrect"}), 400
    if user_id in users:
        return jsonify({"message": "Account creation failed", "cause": "Already same user_id is used"}), 400
    users[user_id] = {"user_id": user_id, "password": password, "nickname": user_id, "comment": ""}
    return jsonify({"message": "Account successfully created", "user": {"user_id": user_id, "nickname": user_id}})

@app.route("/users/<user_id>", methods=["GET"])
@auth_required
def get_user(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({"message": "No user found"}), 404
    if user_id != request.user_id:
        return jsonify({"message": "Authentication failed"}), 401
    return jsonify({"message": "User details by user_id", "user": {
        "user_id": user_id,
        "nickname": user.get("nickname", user_id),
        "comment": user.get("comment", "")
    }})

@app.route("/users/<user_id>", methods=["PATCH"])
@auth_required
def update_user(user_id):
    if request.user_id != user_id:
        return jsonify({"message": "No permission for update"}), 403
    data = request.json or {}
    if "user_id" in data or "password" in data:
        return jsonify({"message": "User updation failed", "cause": "Not updatable user_id and password"}), 400
    if "nickname" not in data and "comment" not in data:
        return jsonify({"message": "User updation failed", "cause": "Required nickname or comment"}), 400

    nickname = data.get("nickname")
    comment = data.get("comment")

    if nickname is not None:
        if len(nickname) > 30:
            return jsonify({"message": "User updation failed", "cause": "Invalid nickname or comment"}), 400
        users[user_id]["nickname"] = nickname if nickname != "" else user_id
    if comment is not None:
        if len(comment) > 100:
            return jsonify({"message": "User updation failed", "cause": "Invalid nickname or comment"}), 400
        users[user_id]["comment"] = comment

    return jsonify({"message": "User successfully updated", "user": [{
        "nickname": users[user_id]["nickname"],
        "comment": users[user_id]["comment"]
    }]}), 200

@app.route("/close", methods=["POST"])
@auth_required
def delete_user():
    user_id = request.user_id
    users.pop(user_id, None)
    return jsonify({"message": "Account and user successfully deleted"}), 200

if __name__ == "__main__":
    app.run(debug=True)
