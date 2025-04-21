from flask import Flask, request, jsonify
import re

app = Flask(__name__)
users = {}

def is_valid_user_id(user_id):
    return re.fullmatch(r'[a-zA-Z0-9]{6,20}', user_id)

def is_valid_password(password):
    return re.fullmatch(r'[!-~]{8,20}', password)  # ASCII printable

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()

    user_id = data.get("user_id")
    password = data.get("password")

    if not user_id or not password:
        return jsonify({
            "message": "Account creation failed",
            "cause": "Required user_id and password"
        }), 400

    if not is_valid_user_id(user_id):
        return jsonify({
            "message": "Account creation failed",
            "cause": "Input length is incorrect or invalid characters in user_id"
        }), 400

    if not is_valid_password(password):
        return jsonify({
            "message": "Account creation failed",
            "cause": "Input length is incorrect or invalid characters in password"
        }), 400

    if user_id in users:
        return jsonify({
            "message": "Account creation failed",
            "cause": "Already same user_id is used"
        }), 400

    users[user_id] = {
        "user_id": user_id,
        "password": password,
        "nickname": user_id,
    }

    return jsonify({
        "message": "Account successfully created",
        "user": {
            "user_id": user_id,
            "nickname": user_id
        }
    }), 200

@app.route("/")
def hello():
    return "API is running!"

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
