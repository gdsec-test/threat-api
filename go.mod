module github.com/gdcorp-infosec/threat-api

go 1.15

require (
	github.com/aws/aws-lambda-go v1.19.1
	github.com/aws/aws-sdk-go v1.35.27
	github.com/gdcorp-infosec/go-ioc v0.0.0-20210201161615-55598c0a06df
	github.com/godaddy/asherah/go/appencryption v0.1.5
	github.com/gorilla/mux v1.7.4 // indirect
	github.com/kr/pretty v0.2.0 // indirect
	github.com/likexian/whois-go v1.7.2
	github.com/likexian/whois-parser-go v1.15.2
	github.com/ns3777k/go-shodan/v4 v4.2.0
	github.com/opentracing/opentracing-go v1.1.0
	github.com/oschwald/geoip2-golang v1.4.0
	github.com/sirupsen/logrus v1.7.0
	github.com/vertoforce/go-splunk v0.0.0-20201016180916-bf97db989317
	github.com/vertoforce/regexgrouphelp v0.1.1
	github.secureserver.net/auth-contrib/go-auth v1.2.1
	github.secureserver.net/threat/go-ldap v0.0.0-20201017001259-d06e7b5f7252
	go.elastic.co/apm v1.9.0
	go.elastic.co/apm/module/apmhttp v1.9.0
	go.elastic.co/apm/module/apmlambda v1.8.0
	go.elastic.co/ecszap v1.0.0
	go.uber.org/zap v1.14.0
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
)
