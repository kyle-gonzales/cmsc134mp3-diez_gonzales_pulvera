import secrets
import sqlite3

from flask import Flask, redirect, render_template, request

app = Flask(__name__)
con = sqlite3.connect("app.db", check_same_thread=False)
app.secret_key = "a really secret key"


def clean_input(text):
    if not isinstance(text, str):
        return text
    return text.replace("<", "&lt;").replace(">", "&gt;")


@app.route("/login", methods=["GET", "POST"])
def login():
    cur = con.cursor()
    if request.method == "GET":
        if request.cookies.get("session_token"):
            res = cur.execute(
                "SELECT username FROM users INNER JOIN sessions ON "
                + "users.id = sessions.user WHERE sessions.token = ?;",
                (request.cookies.get("session_token"),),
            )
            user = res.fetchone()
            if user:
                return redirect("/home")

        return render_template("login.html")
    else:
        username = clean_input(request.form["username"])
        password = clean_input(request.form["password"])
        res = cur.execute(
            "SELECT id from users WHERE username = ? AND password = ?;",
            (username, password),
        )
        user = res.fetchone()
        if user:
            token = secrets.token_hex()
            cur.execute(
                "INSERT INTO sessions (user, token) VALUES (?, ?);",
                (str(user[0]), token),
            )
            con.commit()
            response = redirect("/home")
            response.set_cookie("session_token", token)
            return response
        else:
            return render_template(
                "login.html", error="Invalid username and/or password!"
            )


@app.route("/")
@app.route("/home")
def home():
    cur = con.cursor()
    if request.cookies.get("session_token"):
        res = cur.execute(
            "SELECT users.id, username FROM users INNER JOIN sessions ON "
            + "users.id = sessions.user WHERE sessions.token = ?;",
            (request.cookies.get("session_token"),),
        )
        user = res.fetchone()
        if user:
            res = cur.execute(
                "SELECT message FROM posts WHERE user = ?;", (str(user[0]),)
            )
            posts = res.fetchall()
            return render_template("home.html", username=user[1], posts=posts)

    return redirect("/login")


@app.route("/posts", methods=["POST"])
def posts():
    cur = con.cursor()
    if request.cookies.get("session_token"):
        res = cur.execute(
            "SELECT users.id, username FROM users INNER JOIN sessions ON "
            + "users.id = sessions.user WHERE sessions.token = ?;",
            (request.cookies.get("session_token"),),
        )
        user = res.fetchone()
        if user:
            message = clean_input(request.form["message"])
            cur.execute(
                "INSERT INTO posts (message, user) VALUES (?,?);",
                (message, str(user[0])),
            )
            con.commit()
            return redirect("/home")

    return redirect("/login", error="test")


@app.route("/logout", methods=["GET"])
def logout():
    cur = con.cursor()
    if request.cookies.get("session_token"):
        res = cur.execute(
            "SELECT users.id, username FROM users INNER JOIN sessions ON "
            + "users.id = sessions.user WHERE sessions.token = ?;",
            (request.cookies.get("session_token"),),
        )
        user = res.fetchone()
        if user:
            cur.execute("DELETE FROM sessions WHERE user = ?;", (str(user[0]),))
            con.commit()

    response = redirect("/login")
    response.set_cookie("session_token", "", expires=0)

    return response
