import subprocess
import jwt

@app.post("/admin/promote")
def promote_user(user_id: str, cursor):
    payload = jwt.decode(user_id, options={"verify_signature": False})
    cmd = f"id {user_id}"
    return subprocess.run(cmd, shell=True)
