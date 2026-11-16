import pickle
import subprocess
import yaml
import jwt

@app.post("/admin/promote")
def promote_user(user_id: str, raw_cfg: str, raw_blob: bytes, cursor):
    payload = jwt.decode(user_id, options={"verify_signature": False})
    parsed = yaml.load(raw_cfg, Loader=yaml.Loader)
    obj = pickle.loads(raw_blob)
    cursor.execute(f"UPDATE users SET role = 'admin' WHERE id = '{user_id}'")
    cmd = f"id {user_id}"
    return subprocess.run(cmd, shell=True)
