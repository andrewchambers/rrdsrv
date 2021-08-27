package equery

import (
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	eq := EncryptWithSecret("password", "a secret")
	_, ok := DecryptWithSecret("bad password", eq)
	if ok {
		t.Fatal("decryption worked unexpectedly")
	}
	q, ok := DecryptWithSecret("password", eq)
	if !ok || string(q) != "a secret" {
		t.Fatal("decryption should have worked")
	}
}

func BenchmarkDecrypt(b *testing.B) {
	b.ReportAllocs()
	k := KeyFromSecret("hello")
	eq := EncryptWithKey(&k, "a secret")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, ok := DecryptWithKey(&k, eq)
		if !ok {
			b.Fatal("decryption should have worked")
		}
	}
}
