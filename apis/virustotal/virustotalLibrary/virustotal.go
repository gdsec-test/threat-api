package virustotal

import (
	"context"
	"crypto/sha256"
	"fmt"

	vt "github.com/VirusTotal/vt-go"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
)

const (
	triageModuleName = "virustotal"
	hashPath         = "files/%s"
	urlPath          = "urls/%s"
	domainPath       = "domains/%s"
	ipPath           = "ip_addresses/%s"
)

type VirusTotal struct {
	tb     *toolbox.Toolbox
	apiKey string
	client *vt.Client
}

type MetaData struct {
	Harmless   int64
	Malicious  int64
	Suspicious int64
	Timeout    int64
	Undetected int64
}

func InitializeLastAnalysisMetaData() *MetaData {
	metaDataHolder := &MetaData{}
	return metaDataHolder
}

func NewVirusTotal(tb *toolbox.Toolbox, apiKey string) *VirusTotal {
	virusTotal := new(VirusTotal)
	virusTotal.tb = tb
	virusTotal.apiKey = apiKey
	virusTotal.client = vt.NewClient(apiKey)
	return virusTotal
}

func (m *VirusTotal) GetHash(ctx context.Context, hash string) (*vt.Object, error) {
	span, spanCtx := m.tb.TracerLogger.StartSpan(ctx, "VirustotalLookup", "virustotal", "", "hashEnrich")
	defer span.End(spanCtx)

	url := vt.URL(hashPath, hash)
	obj, err := m.client.GetObject(url)
	if err != nil {
		span.AddError(err)
		return nil, err
	}

	return obj, nil
}

func (m *VirusTotal) GetURL(ctx context.Context, _url string) (*vt.Object, error) {
	span, spanCtx := m.tb.TracerLogger.StartSpan(ctx, "VirustotalLookup", "virustotal", "", "urlEnrich")
	defer span.End(spanCtx)

	hashedUrl := sha256.Sum256([]byte(_url))
	stringHashedUrl := fmt.Sprintf("%x", hashedUrl[:])
	url := vt.URL(urlPath, stringHashedUrl)
	obj, err := m.client.GetObject(url)
	if err != nil {
		span.AddError(err)
		return nil, err
	}

	return obj, nil
}

func (m *VirusTotal) GetDomain(ctx context.Context, domain string) (*vt.Object, error) {
	span, spanCtx := m.tb.TracerLogger.StartSpan(ctx, "VirustotalLookup", "virustotal", "", "domainEnrich")
	defer span.End(spanCtx)

	url := vt.URL(domainPath, domain)
	obj, err := m.client.GetObject(url)
	if err != nil {
		span.AddError(err)
		return nil, err
	}

	return obj, nil
}

func (m *VirusTotal) GetAddress(ctx context.Context, ip string) (*vt.Object, error) {
	span, spanCtx := m.tb.TracerLogger.StartSpan(ctx, "VirustotalLookup", "virustotal", "", "addressEnrich")
	defer span.End(spanCtx)

	url := vt.URL(ipPath, ip)
	obj, err := m.client.GetObject(url)
	if err != nil {
		return nil, err
	}

	return obj, nil
}
