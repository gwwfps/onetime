package onetime

import (
    "crypto/hmac"
    "crypto/sha1"
    "encoding/binary"
    "errors"
    "math"
)

type OneTimePassword struct {
    Digit int
}

func (otp *OneTimePassword) HOTP(secret []byte, count uint64) uint {
    hs := hmacSha1(secret, count)
    return otp.truncate(hs)
}

func hmacSha1(secret []byte, count uint64) []byte {
    mac := hmac.New(sha1.New, secret)
    binary.Write(mac, binary.BigEndian, count)
    return mac.Sum(nil)
}

func (otp *OneTimePassword) truncate(hs []byte) uint {
    sbits := dt(hs)
    snum := uint(sbits[3]) | uint(sbits[2])<<8
    snum |= uint(sbits[1])<<16 | uint(sbits[0])<<24
    return snum % uint(math.Pow(10, float64(otp.Digit)))
}

func New(digit int) (otp OneTimePassword, err error) {
    if digit < 6 {
        err = errors.New("A minimum of 6 digits is required for a valid HTOP code.")
        return
    } else if digit > 9 {
        err = errors.New("An HTOP code cannot be longer than 9 digits.")
        return
    }
    otp = OneTimePassword{digit}
    return
}

func dt(hs []byte) []byte {
    offset := int(hs[19] & 0xf)
    p := hs[offset : offset+4]
    p[0] &= 0x7f
    return p
}
