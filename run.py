from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI()


@app.get("/", response_class=HTMLResponse)
async def login_form():
    return """
    <html>
        <head>
            <title>Login</title>
        </head>
        <body>
            <form action="/login" method="post">
                Username: <input type="text" name="username"><br>
                Password: <input type="password" name="password"><br>
                OTP: <input type="text" name="otp"><br>
                <input type="submit" value="Login">
            </form>
        </body>
    </html>
    """


@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...), otp: str = Form(...)):
    if username == "testuser" and password == "testpass" and otp == "123456":
        return {"message": "Login successful!"}
    return {"message": "Login failed!"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
