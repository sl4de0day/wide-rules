package clean

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os/exec"
)

func QueryUserOrder(ctx context.Context, db *sql.DB, orderID string, ownerID string) *sql.Row {
	return db.QueryRowContext(
		ctx,
		"SELECT id, amount FROM orders WHERE id = $1 AND owner_id = $2",
		orderID,
		ownerID,
	)
}

func RunGitRevision(ctx context.Context, rev string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--verify", rev)
	return cmd.Output()
}

func ValidateAllowedHost(rawURL string, allowed map[string]bool) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return "", false
	}
	if !allowed[u.Hostname()] {
		return "", false
	}
	return u.String(), true
}

func GenerateRandomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
