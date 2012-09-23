package onetime

import "testing"

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
