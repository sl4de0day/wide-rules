package main

import (
	"crypto/tls"
	"database/sql"
	"net/http"
	"os/exec"
)

func handleRequest(db *sql.DB, r *http.Request) {
	q := r.URL.Query().Get("name")
	db.Query("SELECT id FROM users WHERE name = '" + q + "'")
	cmd := exec.Command("sh", "-c", "echo "+q)
	_ = cmd.Run()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	_ = tr
}
