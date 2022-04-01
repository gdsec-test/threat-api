package main

const (
	notBlacklisted = "not listed"
	spammerDomain  = "spammer_domain"
	phishingDomain = "phishing_domain"
	botnetC2Domain = "botnet_cc_domain"
)

type urlHausEntry struct {
	Date      string
	URL       string
	URLStatus string
	Threat    string
	Tags      string
	Host      string
	IPAddress string
	ASnumber  string
	Country   string
}

type VirusTotalSubentry struct {
	Result  string  `json:"result"`
	Percent float32 `json:"percent,string"`
	Link    string  `json:"link"`
}

type UrlSubentry struct {
	Url       string `json:"url"`
	Status    string `json:"url_status"`
	Reference string `json:"urlhaus_reference"`
	FileName  string `json:"filename"`
	First     string `json:"firstseen"`
	Last      string `json:"lastseen"`
}

type UrlhausPayloadEntry struct {
	Status            string               `json:"query_status"`
	Md5               string               `json:"md5_hash"`
	Sha               string               `json:"sha256_hash"`
	FileType          string               `json:"file_type"`
	Size              int                  `json:"file_size,string"`
	Signature         string               `json:"signature"`
	First             string               `json:"first_seen"`
	Last              string               `json:"last_seen"`
	UrlCount          int                  `json:"url_count,string"`
	DownloadUrl       string               `json:"urlhaus_download"`
	VirusTotalResults []VirusTotalSubentry `json:"virustotal"`
	Imphash           string               `json:"imphash"`
	Ssdeep            string               `json:"ssdeep"`
	Tlsh              string               `json:"tlsh"`
	Urls              []UrlSubentry        `json:"urls"`
}

// See https://urlhaus-api.abuse.ch/ for allowed filler values
type UrlhausHostBlacklistSubentry struct {
	SurblStatus    string `json:"surbl"`
	SpamhausStatus string `json:"spamhaus_dbl"`
}

type UrlhausHostUrlSubentry struct {
	Id        string   `json:"id"`
	Reference string   `json:"urlhaus_reference"`
	Status    string   `json:"url_status"`
	Added     string   `json:"date_added"`
	Threat    string   `json:"threat"`
	Reporter  string   `json:"reporter"`
	Larted    string   `json:"larted"`
	Takedown  int      `json:"takedown_time_seconds,string"`
	Tags      []string `json:"tags"`
}

type UrlhausHostEntry struct {
	Status     string                       `json:"query_status"`
	Reference  string                       `json:"urlhaus_reference"`
	First      string                       `json:"first_seen"`
	Count      int                          `json:"url_count,string"`
	Blacklists UrlhausHostBlacklistSubentry `json:"blacklists"`
	Urls       []UrlhausHostUrlSubentry     `json:"urls"`
}

type UrlhausUrlPayloadSubentry struct {
	First      string             `json:"firstseen"`
	FileName   string             `json:"filename"`
	FileType   string             `json:"file_type"`
	Size       int                `json:"response_size,string"`
	Md5        string             `json:"response_md5"`
	Sha256     string             `json:"response_sha256"`
	Download   string             `json:"urlhaus_download"`
	Signature  string             `json:"signature"`
	VirusTotal VirusTotalSubentry `json:"virustotal"`
	Imphash    string             `json:"imphash"`
	Ssdeep     string             `json:"ssdeep"`
	Tlsh       string             `json:"tlsh"`
}

type UrlhausUrlEntry struct {
	Status     string                       `json:"query_status"`
	Id         string                       `json:"id"`
	Reference  string                       `json:"urlhaus_reference"`
	UrlStatus  string                       `json:"url_status"`
	Host       string                       `json:"host"`
	Added      string                       `json:"date_added"`
	Threat     string                       `json:"threat"`
	Blacklists UrlhausHostBlacklistSubentry `json:"blacklists"`
	Reporter   string                       `json:"reporter"`
	Larted     string                       `json:"larted"`
	Takedown   int                          `json:"takedown_time_seconds,string"`
	Tags       []string                     `json:"tags"`
	Payloads   []UrlhausUrlPayloadSubentry  `json:"payloads"`
}

func (m *UrlhausPayloadEntry) GetBadnessScore() float64 {
	score_sum := 0.0
	for _, v := range m.VirusTotalResults {
		score_sum += float64(v.Percent) / 100.0
	}
	return score_sum / float64(len(m.VirusTotalResults))
}

func (m *UrlhausHostEntry) GetBadnessScore() float64 {
	return m.Blacklists.GetBadnessScore()
}

func (m *UrlhausHostBlacklistSubentry) GetBadnessScore() float64 {
	blacklist_hits := 0.0
	blacklist_count := 2.0
	if len(m.SpamhausStatus) > 0 && m.SpamhausStatus != notBlacklisted {
		if m.SpamhausStatus == spammerDomain || m.SpamhausStatus == phishingDomain || m.SpamhausStatus == botnetC2Domain {
			blacklist_hits++
		} else {
			// Treat "abused_legit_spam", "abused_legit_malware", "abused_legit_phishing", "abused_legit_botnetcc", and "abused_redirector" as less bad by half
			blacklist_hits += 0.5
		}
	}
	if m.SurblStatus != notBlacklisted {
		blacklist_hits++
	}
	return blacklist_hits / blacklist_count
}

func (m *UrlhausUrlEntry) GetBadnessScore() float64 {
	return m.Blacklists.GetBadnessScore()
}
