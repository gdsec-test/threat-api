package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/oschwald/geoip2-golang"
	"log"
	"net"
	"net/http"
)

func handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	b, err := json.Marshal(request)
	if err != nil {
		fmt.Println("error:", err)
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       err.Error(),
		}, err
	}

	log.Printf("Received event: %s", b)

	db, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		log.Fatal(err)
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       err.Error(),
		}, err
	}
	defer db.Close()

	ipString := "72.210.63.111"

	ipParam, found := request.QueryStringParameters["ip"]
	if found {
		log.Printf("You specified: %s", ipParam)
		ipString = ipParam
	}

	ip := net.ParseIP(ipString)

	// If you are using strings that may be invalid, check that ip is not nil
	record, err := db.City(ip)
	if err != nil {
		log.Fatal(err)
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       err.Error(),
		}, err
	}

	fmt.Printf("English city name: %v\n", record.City.Names["en"])
	if len(record.Subdivisions) > 0 {
		fmt.Printf("English subdivision name: %v\n", record.Subdivisions[0].Names["en"])
	}
	fmt.Printf("English country name: %v\n", record.Country.Names["en"])

	fmt.Printf("ISO country code: %v\n", record.Country.IsoCode)
	fmt.Printf("Time zone: %v\n", record.Location.TimeZone)
	fmt.Printf("Coordinates: %v, %v\n", record.Location.Latitude, record.Location.Longitude)

	js, err := json.Marshal(record)
	if err != nil {
		log.Fatal(err)
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
