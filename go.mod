module github.com/gdcorp-infosec/threat-api

go 1.15

require (
	github.com/aws/aws-lambda-go v1.19.1
	github.com/aws/aws-sdk-go v1.35.27
	github.com/gdcorp-infosec/threat-util v0.0.0-20210119215543-bf06888df5ab
	github.com/godaddy/asherah/go/appencryption v0.1.5
	github.com/gorilla/mux v1.7.4 // indirect
	github.com/kr/pretty v0.2.0 // indirect
	github.com/likexian/whois-go v1.7.2
	github.com/likexian/whois-parser-go v1.15.2
	github.com/opentracing/opentracing-go v1.1.0
	github.com/oschwald/geoip2-golang v1.4.0
	github.com/sirupsen/logrus v1.7.0
	github.com/vertoforce/go-ioc v0.0.0-20201028230052-ad588a5f691d
	github.com/vertoforce/regexgrouphelp v0.1.1
	go.elastic.co/apm v1.9.0
	go.elastic.co/apm/module/apmlambda v1.8.0
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
)
