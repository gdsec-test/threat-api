module github.com/gdcorp-infosec/threat-api

go 1.15

require (
	github.com/aws/aws-lambda-go v1.19.1
	github.com/oschwald/geoip2-golang v1.4.0 // indirect
	github.secureserver.net/threat/util v0.0.0-20201017001357-49a72cdebd27
	go.elastic.co/apm/module/apmlambda v1.8.0 // indirect
)

replace github.secureserver.net/threat/util => ../../threat/util
