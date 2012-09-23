package onetime

import (
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "strings"
    "testing"
    "time"
)

// TestHOTP validates the HOTP implementation against test values provided in 
// Appendix D of RFC-4226.
func TestHOTP(t *testing.T) {
    expected := []uint{
        755224,
        287082,
        359152,
        969429,
        338314,
        254676,
        287922,
        162583,
        399871,
        520489,
    }
    secret := []byte("12345678901234567890")

    otp, _ := Simple(6)

    for i, exp := range expected {
        if v := otp.HOTP(secret, uint64(i)); v != exp {
            t.Errorf("HOTP(secret, %v) = %v, want %v", i, v, exp)
        }
    }
}

// TestTOTP validates the TOTP implementation against test values provided in 
// Appendix B of RFC-6238.
func TestTOTP(t *testing.T) {
    expected := []uint{
        94287082,
        46119246,
        90693936,
        7081804,
        68084774,
        25091201,
        14050471,
        67062674,
        99943326,
        89005924,
        91819424,
        93441116,
        69279037,
        90698825,
        38618901,
        65353130,
        77737706,
        47863826,
    }

    times := []time.Time{
        time.Unix(59, 0),
        time.Unix(1111111109, 0),
        time.Unix(1111111111, 0),
        time.Unix(1234567890, 0),
        time.Unix(2000000000, 0),
        time.Unix(20000000000, 0),
    }

    digit := 8
    step, _ := time.ParseDuration("30s")
    otps := []OneTimePassword{
        OneTimePassword{digit, step, time.Unix(0, 0), sha1.New},
        OneTimePassword{digit, step, time.Unix(0, 0), sha256.New},
        OneTimePassword{digit, step, time.Unix(0, 0), sha512.New},
    }

    keyPart := "1234567890"
    secrets := [][]byte{
        []byte(strings.Repeat(keyPart, 2)),
        []byte(strings.Repeat(keyPart, 4)[:32]),
        []byte(strings.Repeat(keyPart, 8)[:64]),
    }

    for i, exp := range expected {
        otp := otps[i%3]
        secret := secrets[i%3]
        now := times[i/3]
        if v := otp.HOTP(secret, otp.steps(now)); v != exp {
            t.Errorf("%s", uint64(now.Unix()-otp.BaseTime.Unix()))
            t.Errorf("TOTP(secret) = %v, want %v (time: %v, hash: %v)", v, exp, now, otp.Hash)
        }
    }
}
