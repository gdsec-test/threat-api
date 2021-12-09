package passivetotalLibrary

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDomainResponseFormatting(t *testing.T) {
	report := PDNSReport{
		QueryValue: "localhost.lan",
		FirstSeen:  "1776-04-01",
		LastSeen:   "2021-12-08",
	}
	report.Results = append(report.Results, PDNSReportResult{
		Value:     "127.0.0.1",
		FirstSeen: "1776-04-01",
		LastSeen:  "2021-01-06",
		Source:    []string{"nonsense.com"},
	})
	report.Results = append(report.Results, PDNSReportResult{
		Value:     "255.255.255.255",
		FirstSeen: "1980-08-15",
		LastSeen:  "2021-12-08",
		Source:    []string{"nonsense.com"},
	})
	other := report.MakeDomainResponse()
	fmt.Print(other)
}

func TestGetPassiveDNSSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(rw http.ResponseWriter, req *http.Request) {
			if req.URL.Path == PassiveDNSPath {
				message := `{"pager": null,"queryValue": "godaddy.com","queryType": "domain","firstSeen": "2010-06-23 20:14:31","lastSeen": "2021-09-09 14:07:23","totalRecords": 50,"results": [{"firstSeen": "2021-09-09 14:07:23","lastSeen": "2021-09-09 14:07:23","source": ["pingly"],"value": "godaddy.com","collected": "2021-09-09 21:07:23","recordType": "TXT (SPF1)","resolve": "184.168.131.0/24","resolveType": "domain","recordHash": "3ef1b290ef5c0ab8b964a9afa5f1f0be2567f7781d6975de2011a8cda08fe052"}]}`
				rw.WriteHeader(http.StatusOK)
				rw.Write([]byte(message))
			}
		}))
	defer server.Close()

	ctx := context.TODO()

	pdnsResult, err := GetPassiveDNS(ctx, server.URL, "godaddy.com", "user", "key", http.DefaultClient)

	assert.Equal(t, err, nil, "error in getting the passivedns data")
	assert.Equal(t, pdnsResult.QueryValue, "godaddy.com", "test failed at passivedns queryvalue mismatch")
	assert.Equal(t, pdnsResult.Results[0].Resolve, "184.168.131.0/24", "test failed at resolvetype mismatch")
}

func TestGetPassiveDNSStatusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(rw http.ResponseWriter, req *http.Request) {
			if req.URL.Path == PassiveDNSPath {
				message := `test`
				rw.WriteHeader(http.StatusBadRequest)
				rw.Write([]byte(message))
			}
		}))
	defer server.Close()

	ctx := context.TODO()
	_, err := GetPassiveDNS(ctx, server.URL, "godaddy.com", "user", "key", http.DefaultClient)

	assert.NotEqual(t, err, nil, "test failed at checking the GetPassiveDNS error path")
}

func TestGetPassiveDNSDecodeError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(rw http.ResponseWriter, req *http.Request) {
			if req.URL.Path == PassiveDNSPath {
				message := `test`
				rw.WriteHeader(http.StatusOK)
				rw.Write([]byte(message))
			}
		}))
	defer server.Close()

	ctx := context.TODO()
	_, err := GetPassiveDNS(ctx, server.URL, "godaddy.com", "user", "key", http.DefaultClient)

	assert.NotEqual(t, err, nil, "test failed at GetPassiveDNS decode error test")
}
