package onetime

import (
    "crypto/hmac"
    "crypto/sha1"
    "encoding/binary"
    "errors"
    "hash"
    "math"
    "time"
)

type OneTimePassword struct {
    Digit    int
    TimeStep time.Duration
    BaseTime time.Time
    Hash     func() hash.Hash
}

func (otp *OneTimePassword) HOTP(secret []byte, count uint64) uint {
    hs := otp.hmacSum(secret, count)
    return otp.truncate(hs)
}

func (otp *OneTimePassword) hmacSum(secret []byte, count uint64) []byte {
    mac := hmac.New(otp.Hash, secret)
    binary.Write(mac, binary.BigEndian, count)
    return mac.Sum(nil)
}

func (otp *OneTimePassword) truncate(hs []byte) uint {
    sbits := dt(hs)
    snum := uint(sbits[3]) | uint(sbits[2])<<8
    snum |= uint(sbits[1])<<16 | uint(sbits[0])<<24
    return snum % uint(math.Pow(10, float64(otp.Digit)))
}

func Simple(digit int) (otp OneTimePassword, err error) {
    if digit < 6 {
        err = errors.New("A minimum of 6 digits is required for a valid HTOP code.")
        return
    } else if digit > 9 {
        err = errors.New("An HTOP code cannot be longer than 9 digits.")
        return
    }
    step, _ := time.ParseDuration("30s")
    otp = OneTimePassword{digit, step, time.Unix(0, 0), sha1.New}
    return
}

func (otp *OneTimePassword) TOTP(secret []byte) uint {
    return otp.HOTP(secret, otp.steps(time.Now()))
}

func (otp *OneTimePassword) steps(now time.Time) uint64 {
    elapsed := now.Sub(otp.BaseTime)
    return uint64(math.Floor(elapsed.Seconds() / otp.TimeStep.Seconds()))
}

func dt(hs []byte) []byte {
    offset := int(hs[len(hs)-1] & 0xf)
    p := hs[offset : offset+4]
    p[0] &= 0x7f
    return p
}
