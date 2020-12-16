module github.com/gdcorp-infosec/threat-api

go 1.15

require (
	github.com/aws/aws-lambda-go v1.19.1
	github.com/aws/aws-sdk-go v1.35.27
	github.com/godaddy/asherah/go/appencryption v0.1.5
	github.com/opentracing/opentracing-go v1.1.0
	github.com/oschwald/geoip2-golang v1.4.0
	github.com/sirupsen/logrus v1.7.0
	github.secureserver.net/threat/util v0.0.0-20201207211930-95ef4e936f48
	go.elastic.co/apm v1.9.0
	go.elastic.co/apm/module/apmlambda v1.8.0
)

// replace github.secureserver.net/threat/util => ../../threat/util
