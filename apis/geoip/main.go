package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/log"
	"github.com/oschwald/geoip2-golang"
	"github.com/sirupsen/logrus"
	"github.secureserver.net/threat/util/lambda/toolbox"

	// This line adds apm tracing to this lambda
	// Yep, it's that simple!
	// Note that you must have the `ELASTIC_APM_SERVER_URL` and `ELASTIC_APM_API_KEY` env vars set
	"go.elastic.co/apm"
	_ "go.elastic.co/apm/module/apmlambda"
)

func handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Get the toolbox
	// This helps standardize things accross services
	t := toolbox.GetToolbox()
	// Defer sending of tracing info
	defer func() {
		apm.DefaultTracer.Flush(nil)
		apm.DefaultTracer.SendMetrics(nil)
		apm.DefaultTracer.Close()
	}()

	t.Logger.Info("Starting handling of request")

	// Start transaction to process geoip request
	geoipTx := t.Tracer.StartSpan("GeoIP")
	defer geoipTx.Finish()
	ctx = opentracing.ContextWithSpan(ctx, geoipTx)

	// Start a span
	span, _ := opentracing.StartSpanFromContext(ctx, "OpenDB")
	// Open DB
	db, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		apm.CaptureError(ctx, err).Send()
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       err.Error(),
		}, err
	}
	defer db.Close()
	span.Finish()

	span, _ = opentracing.StartSpanFromContext(ctx, "GetUserIP")
	ipString := "72.210.63.111" // Default ip
	ipParam, found := request.QueryStringParameters["ip"]
	if found {
		t.Logger.WithField("IP", ipParam).Info("Got supplied IP")
		ipString = ipParam
	}
	span.LogFields(log.String("IP", ipParam))
	ip := net.ParseIP(ipString)
	span.Finish()

	// If you are using strings that may be invalid, check that ip is not nil
	span, _ = opentracing.StartSpanFromContext(ctx, "ProcessUserIP")
	record, err := db.City(ip)
	if err != nil {
		apm.CaptureError(ctx, err).Send()
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       err.Error(),
		}, err
	}
	span.Finish()

	t.Logger.WithFields(logrus.Fields{
		"EnglishCity":    record.City.Names["en"],
		"EnglishCountry": record.Country.Names["en"],
		"ISOCountryCode": record.Country.IsoCode,
		"TimeZone":       record.Location.TimeZone,
		"Lat":            record.Location.Latitude,
		"Long":           record.Location.Longitude,
	}).Info("Found result")

	js, err := json.Marshal(record)
	if err != nil {
		apm.CaptureError(ctx, err).Send()
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       err.Error(),
		}, err
	}

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Body:       string(js),
	}, nil
}

func main() {
	lambda.Start(handler)
}
