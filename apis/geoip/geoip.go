package main

import (
	"context"
	"fmt"
	"net"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/oschwald/geoip2-golang"
)

const (
	triageModuleName = "geoip"
)

type GeoIPInfo struct {
	IP             string
	EnglishCity    string
	EnglishCountry string
	ISOCountryCode string
	TimeZone       string
	Lat            float64
	Long           float64
}

// Lookup performs a geoIP search on passed IPs
func Lookup(ctx context.Context, ips []string) []*GeoIPInfo {

	var span *appsectracing.Span
	span, ctx = tb.TracerLogger.StartSpan(ctx, "GeoIPDBSession", "geoip", "db", "session")
	defer span.End(ctx)

	geoipResults := []*GeoIPInfo{}
	// load geoip Database
	db, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		return append(geoipResults, &GeoIPInfo{
			IP:             fmt.Sprintf("ERROR: %s", err),
			EnglishCity:    fmt.Sprintf("ERROR: %s", err),
			EnglishCountry: fmt.Sprintf("ERROR: %s", err),
		})
		span.AddError(err)
	}
	defer db.Close()

	for _, ip := range ips {
		// Check context
		select {
		case <-ctx.Done():
			break
		default:
		}

		span, ctx = tb.TracerLogger.StartSpan(ctx, "GeoIPLookup", "geoip", "ip", "lookup")
		addErrRow := func(err error) {
			geoipResults = append(geoipResults, &GeoIPInfo{
				IP:             ip,
				EnglishCity:    fmt.Sprintf("ERROR: %s", err),
				EnglishCountry: fmt.Sprintf("ERROR: %s", err),
			})
			span.AddError(err)
			span.End(ctx)
		}

		record, err := db.City(net.ParseIP(ip))
		if err != nil {
			addErrRow(err)
			continue
		}
		geoipResults = append(geoipResults, &GeoIPInfo{
			IP:             ip,
			EnglishCity:    record.City.Names["en"],
			EnglishCountry: record.Country.Names["en"],
			ISOCountryCode: record.Country.IsoCode,
			TimeZone:       record.Location.TimeZone,
			Lat:            record.Location.Latitude,
			Long:           record.Location.Longitude,
		})
		span.End(ctx)
	}

	return geoipResults
}
