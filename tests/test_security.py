import io
import app as tv
import os

VIEWER_PW = os.environ["DEMO_VIEWER_PASSWORD"]
OWNER_PW = os.environ["DEMO_OWNER_PASSWORD"]

def login(client, username, password):
    return client.post("/login", data={"username":username,"password":password}, follow_redirects=True)

def test_viewer_cannot_upload(client):
    login(client, "viewer", VIEWER_PW)
    response = client.get("/upload")
    assert response.status_code == 403

def test_private_document_denied_to_unshared_viewer(client):
    login(client, "owner", OWNER_PW)
    response = client.post("/upload", data={
        "title":"Private", "category":"Finance",
        "file":(io.BytesIO(b"secret-content"), "secret.txt")
    }, content_type="multipart/form-data", follow_redirects=True)
    assert response.status_code == 200
    with tv.db() as c:
        doc = c.execute("SELECT id FROM documents").fetchone()
    client.get("/logout")
    login(client, "viewer", VIEWER_PW)
    denied = client.get(f"/document/{doc['id']}/download")
    assert denied.status_code == 404
    with tv.db() as c:
        event = c.execute("SELECT action FROM audit_logs WHERE action='DOWNLOAD_DENIED'").fetchone()
    assert event is not None

def test_owner_can_grant_and_revoke_access(client):
    login(client, "owner", OWNER_PW)
    client.post("/upload", data={"title":"Shared","category":"HR",
        "file":(io.BytesIO(b"hello"),"hello.txt")}, content_type="multipart/form-data")
    with tv.db() as c:
        doc_id = c.execute("SELECT id FROM documents").fetchone()["id"]
    client.post(f"/document/{doc_id}/permissions", data={"username":"viewer","can_read":"on"})
    client.get("/logout")
    login(client, "viewer", VIEWER_PW)
    assert client.get(f"/document/{doc_id}/download").status_code == 200
    client.get("/logout")
    login(client, "owner", OWNER_PW)
    client.post(f"/document/{doc_id}/permissions", data={"username":"viewer"})
    client.get("/logout")
    login(client, "viewer", VIEWER_PW)
    assert client.get(f"/document/{doc_id}/download").status_code == 404

def test_audit_chain_detects_modified_entry(client):
    tv.audit(1, "TEST_EVENT", details={"ok":True})
    assert tv.verify_audit_chain()
    with tv.db() as c:
        c.execute("UPDATE audit_logs SET details='{}' WHERE id=1")
        c.commit()
    assert not tv.verify_audit_chain()
