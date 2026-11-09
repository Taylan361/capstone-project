import sqlite3
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)
api_key = "sk-demo-placeholder-not-a-real-secret-123456"


def evaluate_expression(user_input):
    return eval(user_input)


def run_command(command):
    return subprocess.run(command, shell=True, check=False)


def lookup_user(conn: sqlite3.Connection, user_id: str):
    cursor = conn.cursor()
    return cursor.execute(f"SELECT id, username FROM users WHERE id = {user_id}")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return render_template_string(f"<h2>Results for {q}</h2>")
