module github.com/philiaspace/authphi

go 1.22

require (
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/philiaspace/phi-core v0.0.0
	github.com/philiaspace/phi-middleware v0.0.0
	github.com/philiaspace/phi-utils v0.0.0
)

replace (
	github.com/philiaspace/phi-core => ../../libs/phi-core
	github.com/philiaspace/phi-middleware => ../../libs/phi-middleware
	github.com/philiaspace/phi-utils => ../../libs/phi-utils
)
