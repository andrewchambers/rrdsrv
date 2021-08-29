package querysign

import (
	"testing"
)

func TestQuerySignatures(t *testing.T) {
	secret := []byte("secret")
	signed := SignQuery(secret, []byte("/api/v1/ping"), []byte("foo=bar&baz=bang&"))
	if !ValidateSignedQuery(secret, []byte("/api/v1/ping"), signed) {
		t.Fatalf("validation of %q failed", signed)
	}
	if ValidateSignedQuery(secret, []byte("/api/v2/ping"), signed) {
		t.Fatalf("validation of %q should have failed", signed)
	}
	signed[2] = 'x'
	if ValidateSignedQuery(secret, []byte("/api/v1/ping"), signed) {
		t.Fatalf("validation of %q should have failed", signed)
	}
}
