onetime
=======

An one-time password generation library written in Go, implementing 
HOTP ([RFC-4226](http://tools.ietf.org/html/rfc4226)) and 
TOTP ([RFC-6238](http://tools.ietf.org/html/rfc6238)).

Example usage 
-------------

Simple 6-digit HOTP code:
```go
import "onetime"

var secret = []byte("SOME_SECRET")
var counter = 123456
var otp = onetime.Simple(6) 
var code = otp.HOTP(secret, counter)
```

Google authenticator style 8-digit TOTP code:
```go
import "onetime"

var secret = []byte("SOME_SECRET")
var otp = onetime.Simple(8) 
var code = otp.TOTP(secret)
```

9-digit 5-second-step TOTP starting on midnight 2000-01-01, using SHA-256:
```go
import (
    "crypto/sha256"
    "onetime"
    "time"
)

var secret = []byte("SOME_SECRET")
var ts, _ = time.ParseDuration("5s")
var t = time.Date(2000, time.January, 1, 1, 0, 0, 0, time.UTC)
var otp = onetime.OneTimePassword{Digit: 9, TimeStep: ts, BaseTime: t, Hash: sha256.New} 
var code = otp.TOTP(secret)
```

Documentation
-------------
Package doc can be found [at pkgdoc.org](http://go.pkgdoc.org/github.com/gwwfps/onetime).

License
-------
This library is released under a simplified BSD license.