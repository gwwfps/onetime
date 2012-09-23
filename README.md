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
var hotp = otp.HOTP(secret, counter)
```

Google authenticator style 8-digit TOTP code:
```go
import "onetime"

var secret = []byte("SOME_SECRET")
var otp = onetime.Simple(8) 
var hotp = otp.TOTP(secret)
```

Documentation
-------------
Package doc can be found [at pkgdoc.org](http://go.pkgdoc.org/github.com/gwwfps/onetime).

License
-------
This library is released under a simplified BSD license.