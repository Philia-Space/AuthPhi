module github.com/philiaspace/authphi

go 1.22

require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/philiaspace/phi-core v0.0.0
	github.com/philiaspace/phi-middleware v0.0.0
	github.com/philiaspace/phi-utils v0.0.0
	golang.org/x/crypto v0.31.0
)

replace (
	github.com/philiaspace/phi-core => ../../libs/phi-core
	github.com/philiaspace/phi-middleware => ../../libs/phi-middleware
	github.com/philiaspace/phi-utils => ../../libs/phi-utils
)
