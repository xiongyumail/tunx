package auth

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatalf("hash %s", h)
	}
	if !CheckPassword(h, "correct horse") || CheckPassword(h, "wrong") || CheckPassword("garbage", "correct horse") {
		t.Fatal("password check wrong")
	}
	if _, err := HashPassword(""); err == nil {
		t.Fatal("empty password accepted")
	}
}

// RFC 6238 appendix B, SHA-1, truncated to 6 digits.
func TestTOTPVectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, v := range []struct {
		t    int64
		code string
	}{{59, "287082"}, {1111111109, "081804"}, {1234567890, "005924"}, {2000000000, "279037"}} {
		got, err := TOTPCode(secret, time.Unix(v.t, 0))
		if err != nil || got != v.code {
			t.Errorf("t=%d: got %s, want %s", v.t, got, v.code)
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	code, _ := TOTPCode(secret, now)
	step, ok := VerifyTOTP(secret, code, now, 0)
	if !ok {
		t.Fatal("current code rejected")
	}
	if _, ok := VerifyTOTP(secret, code, now, step); ok {
		t.Fatal("replayed code accepted")
	}
	if _, ok := VerifyTOTP(secret, code, now.Add(30*time.Second), 0); !ok {
		t.Fatal("previous step not accepted within skew")
	}
	if _, ok := VerifyTOTP(secret, code, now.Add(2*time.Minute), 0); ok {
		t.Fatal("stale code accepted")
	}
	if _, ok := VerifyTOTP(secret, "12345", now, 0); ok {
		t.Fatal("short code accepted")
	}
	if !strings.HasPrefix(TOTPURI("tunx-hub", "admin", secret), "otpauth://totp/tunx-hub:admin?") {
		t.Fatal(TOTPURI("tunx-hub", "admin", secret))
	}
}
