package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
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
	httpClient := t.GetHTTPClient(nil)
	// Defer sending of tracing info
	defer func() {
		t.Tracer.Flush(nil)
		t.Tracer.SendMetrics(nil)
		t.Tracer.Close()
	}()

	t.Logger.Info("Starting handling of request")

	// Start transaction to process geoip request
	geoipTx := t.Tracer.StartTransaction("GeoIP", "job")
	defer geoipTx.End()
	ctx = apm.ContextWithTransaction(ctx, geoipTx)

	// Make a sample HTTP request
	// The request should be traced
	req, err := http.NewRequestWithContext(ctx, "GET", os.Getenv("ELASTIC_APM_SERVER_URL"), nil)
	if err != nil {
		// Capture error with tracer
		apm.CaptureError(ctx, err).Send()

		// Log error
		t.Logger.WithError(err).Error("Failed to make request")
		return events.APIGatewayProxyResponse{}, nil
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		// Capture error with tracer
		apm.CaptureError(ctx, err).Send()

		// Log error
		t.Logger.WithError(err).Error("Failed to make request")
		return events.APIGatewayProxyResponse{}, nil
	}
	t.Logger.WithField("StatusCode", resp.StatusCode).Info("Got response")
	resp.Body.Close()

	// Start a span
	span := geoipTx.StartSpan("OpenDB", "job", nil)
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
	span.End()

	span = geoipTx.StartSpan("GetUserIP", "job", nil)
	ipString := "72.210.63.111" // Default ip
	ipParam, found := request.QueryStringParameters["ip"]
	if found {
		t.Logger.WithField("IP", ipParam).Info("Got supplied IP")
		ipString = ipParam
	}
	span.Context.SetLabel("IP", ipString)
	ip := net.ParseIP(ipString)
	span.End()

	// If you are using strings that may be invalid, check that ip is not nil
	span = geoipTx.StartSpan("ProcessUserIP", "job", nil)
	record, err := db.City(ip)
	if err != nil {
		apm.CaptureError(ctx, err).Send()
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       err.Error(),
		}, err
	}
	span.End()

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
