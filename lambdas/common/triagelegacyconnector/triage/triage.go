package triage

import (
	"context"
)

// Data is data we found on an ioc
// This must be stored in a separate package due to import cycle constraints
type Data struct {
	// A brief description of this data
	Title string
	// Basically a bullet list of key insights about this set of data
	// Leave blank if no insights were found
	// If this is blank, it will not be listed on the list of insights
	Metadata []string
	// The actual data
	// A full csv, json block, or other enriched data
	// Leave blank if no data was found
	// If this is blank it will be ignored
	DataType DataType
	Data     string
}

// DataType is the type of data of this data (default: csv)
type DataType string

// DataTypes
const (
	CSVType  DataType = "csv"
	PNGType  DataType = "png"
	TextType DataType = "txt"
	JSONType DataType = "json"
)

// IOCType is the
type IOCType string

// IOCTypes
const (
	UnknownType IOCType = "UNKNOWN"
	DomainType  IOCType = "DOMAIN"
	EmailType   IOCType = "EMAIL"
	CVEType     IOCType = "CVE"
	CWEType     IOCType = "CWE"
	CAPECType   IOCType = "CAPEC"
	CPEType     IOCType = "CPE"
	URLType     IOCType = "URL"
	MD5Type     IOCType = "MD5"
	SHA1Type    IOCType = "SHA1"
	SHA256Type  IOCType = "SHA256"
	SHA512Type  IOCType = "SHA512"
	IPType      IOCType = "IP"
	// This is for godaddy machine hostnames
	HostnameType IOCType = "HOSTNAME"
	// AWS hostname
	AWSHostnameType IOCType = "AWSHOSTNAME"
	// GoDaddy username
	GoDaddyUsernameType IOCType = "GODADDY_USERNAME"
	// Mitre IOCs
	MitreMatrixType       IOCType = "MITRE_MATRIX"
	MitreTacticType       IOCType = "MITRE_TACTIC"
	MitreSubTechniqueType IOCType = "MITRE_SUBTECHNIQUE"
	MitreTechniqueType    IOCType = "MITRE_TECHNIQUE"
	MitreMitigationType   IOCType = "MITRE_MITIGATION"
	MitreGroupType        IOCType = "MITRE_GROUP"
	MitreSoftwareType     IOCType = "MITRE_SOFTWARE"
)

type IOCTypes []IOCType

var AllIOCTypes = IOCTypes{
	DomainType,
	EmailType,
	CVEType,
	CWEType,
	CAPECType,
	CPEType,
	URLType,
	MD5Type,
	SHA1Type,
	SHA256Type,
	SHA512Type,
	IPType,
	HostnameType,
	AWSHostnameType,
	GoDaddyUsernameType,
	MitreTacticType,
	MitreTechniqueType,
	MitreSubTechniqueType,
	MitreMitigationType,
	MitreMatrixType,
	MitreGroupType,
	MitreSoftwareType,
}

// IOCTypes.ToString() returns the human-readable strings for all supported IOCs.
func (all IOCTypes) ToString() []string {
	var result []string
	for _, m := range all {
		result = append(result, string(m))
	}
	return result
}

// Request Represents a request to triage some iocs, and info about the requester.
// Some triage functions require special permissions so we need to make sure the user has those permissions
type Request struct {
	IOCs     []string
	IOCsType IOCType
	// JWT from request
	JWT string
	// Whether to output full dumps of the fetched data
	Verbose bool
}

// Module is a triage module specializing in gathering some type of data for a particular ioc type
// A module can implement the work to perform the enrichment itself, or may call out to another plugin to get the data
// It's mostly an abstraction to allow multiple modules to enrich the same ioc type and format it consistently
// The module is the building block for the master `triage` command
type Module interface {
	// Triage is the base command to return whatever data we can find about the ioc
	// If no data was found it should not return any []*Data
	// It should only return an error if there is a critical error, otherwise it should return whatever data it can (partial results)
	Triage(ctx context.Context, triageRequest *Request) ([]*Data, error)
	// Supports returns the IOCTypes this modules support
	Supports() []IOCType
	// Get the documentation of this triage module
	GetDocs() *Doc
}

// Doc is the documentation of a triage module
type Doc struct {
	Name string
	// A short (<60 characters) description of the module
	Description string
}

// Supports returns true of the module supports the provided iocType
func Supports(m Module, iocType IOCType) bool {
	for _, t := range m.Supports() {
		if t == iocType {
			return true
		}
	}
	return false
}
