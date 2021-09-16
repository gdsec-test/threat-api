package passivetotalLibrary

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

func TestGetUniquePassiveDNSSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(rw http.ResponseWriter, req *http.Request) {
			if req.URL.Path == UniquePassiveDNSPath {
				message := `{"pager":null,"queryValue":"godaddy.com","queryType":"domain","total":25,"results":["108.179.246.60","24.249.92.34","97.74.104.201","97.74.104.221","68.226.197.225","50.116.94.255","208.109.4.218","5.181.218.106","69.175.22.250","85.119.149.96","97.74.104.218","184.168.227.107","50.63.202.83","24.248.135.158","24.248.135.155","24.249.94.184","74.220.199.6","208.109.192.70","192.0.78.25","192.0.78.24","24.249.94.119","208.109.4.201","198.71.248.82","67.215.65.130","104.238.65.160"],"frequency":[["108.179.246.60",1],["24.249.92.34",1],["97.74.104.201",1],["97.74.104.221",1],["68.226.197.225",1],["50.116.94.255",1],["208.109.4.218",1],["5.181.218.106",1],["69.175.22.250",1],["85.119.149.96",1],["97.74.104.218",1],["184.168.227.107",1],["50.63.202.83",1],["24.248.135.158",1],["24.248.135.155",1],["24.249.94.184",1],["74.220.199.6",1],["208.109.192.70",1],["192.0.78.25",1],["192.0.78.24",1],["24.249.94.119",1],["208.109.4.201",1],["198.71.248.82",1],["67.215.65.130",1],["104.238.65.160",1]]}`
				rw.WriteHeader(http.StatusOK)
				rw.Write([]byte(message))
			}
		}))
	defer server.Close()

	ctx := context.TODO()

	pdnsUniqueResult, err := GetUniquePassiveDNS(ctx, server.URL, "godaddy.com", "user", "key", http.DefaultClient)

	assert.Equal(t, err, nil, "error in getting the unique passivedns data")
	assert.Equal(t, pdnsUniqueResult.QueryValue, "godaddy.com", "test failed at uniquepassivedns mismatch")
	assert.Equal(t, pdnsUniqueResult.Total, 25, "test failed at total count mismatch")
}

func TestGetUniquePassiveDNSStatusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(rw http.ResponseWriter, req *http.Request) {
			if req.URL.Path == UniquePassiveDNSPath {
				message := `test`
				rw.WriteHeader(http.StatusBadRequest)
				rw.Write([]byte(message))
			}
		}))
	defer server.Close()

	ctx := context.TODO()

	_, err := GetUniquePassiveDNS(ctx, server.URL, "godaddy.com", "user", "key", http.DefaultClient)

	assert.NotEqual(t, err, nil, "test failed at checking the GetUniquePassiveDNS error path")
}

func TestGetUniquePassiveDNSDecodeError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(rw http.ResponseWriter, req *http.Request) {
			if req.URL.Path == UniquePassiveDNSPath {
				message := `test`
				rw.WriteHeader(http.StatusOK)
				rw.Write([]byte(message))
			}
		}))
	defer server.Close()

	ctx := context.TODO()
	_, err := GetUniquePassiveDNS(ctx, server.URL, "godaddy.com", "user", "key", http.DefaultClient)

	assert.NotEqual(t, err, "test failed at GetUniquePassiveDNS decode error test")
}
