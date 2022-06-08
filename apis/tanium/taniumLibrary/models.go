package taniumLibrary

type Common struct {
	Name string `json:"name"`
	Id   int    `json:"id"`
}

type ContentSet struct {
	Common
}

type Query struct {
	Platform string `json:"platform"`
	Script   string `json:"script"`
	Type     string `json:"script_type"`
}

type SubColumn struct {
	Name       string `json:"name"`
	Hidden     bool   `json:"hidden_flag"`
	IgnoreCase bool   `json:"ignore_case_flag"`
	Index      int    `json:"index"`
	ValueType  string `json:"value_type"`
}

type Sensor struct {
	Common
	client              *TaniumClient
	Category            string      `json:"category"`
	ContentSet          ContentSet  `json:"content_set"`
	Delimiter           string      `json:"delimiter"`
	Description         string      `json:"description"`
	HashInt             int         `json:"hash"`
	HashStr             string      `json:"hash"`
	Hidden              bool        `json:"hidden_flag"`
	IgnoreCase          bool        `json:"ignore_case_flag"`
	KeepDuplicates      bool        `json:"keep_duplicates_flag"`
	MaxAgeSeconds       int         `json:"max_age_seconds"`
	ParameterDefinition string      `json:"parameter_definition"`
	Queries             []Query     `json:"queries"`
	SourceId            int         `json:"source_id"`
	StringCount         int         `json:"string_count"`
	SubColumns          []SubColumn `json:"subcolumns"`
	ValueType           string      `json:"value_type"`
}

type SensorRef struct {
	Name      string      `json:"name"`
	RealMsAvg int         `json:"real_ms_avg"`
	StartChar interface{} `json:"start_char"`
}

type Filter struct {
	client          *TaniumClient
	Aggregation     string `json:"aggregation"`
	AllTimes        bool   `json:"all_times_flag"`
	AllValues       bool   `json:"all_values_flag"`
	Delimiter       string `json:"delimiter"`
	DelimiterIndex  int    `json:"delimiter_index"`
	EndTime         string `json:"end_time"`
	IgnoreCase      bool   `json:"ignore_case_flag"`
	MaxAgeSeconds   int    `json:"max_age_seconds"`
	Not             bool   `json:"not_flag"`
	Operator        string `json:"operator"`
	StartTime       string `json:"start_time"`
	SubString       bool   `json:"substring_flag"`
	SubStringLength int    `json:"substring_length"`
	SubStringStart  int    `json:"substring_start"`
	UTF8            bool   `json:"utf8_flag"`
	Value           string `json:"value"`
	ValueType       string `json:"value_type"`
	Sensor          Sensor `json:"sensor"`
}

type Select struct {
	Filter Filter `json:"filter"`
	Group  Group  `json:"group"`
	Sensor Sensor `json:"sensor"`
}

type Privilege struct {
	Name string `json:"name"`
}

type ContentSetPrivilege struct {
	Privilege Privilege `json:"content_set_privilege"`
}

type EffectiveContentSetPrivilege struct {
	ContentSet           ContentSet            `json:"content_set"`
	ContentSetPrivileges []ContentSetPrivilege `json:"content_set_privilege_list"`
}

type EffectiveContentSetPrivilegeObj struct {
	EffectiveContentSetPrivilege EffectiveContentSetPrivilege `json:"effective_content_set_privilege"`
}

type MetadataItem struct {
	Admin bool   `json:"admin_flag"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Metadata struct {
	Item MetadataItem `json:"item"`
}

type Permission struct {
	Name string `json:"permission"`
}

type User struct {
	Common
	client                        *TaniumClient
	ActiveSessionCount            int                            `json:"active_session_count"`
	AsPersona                     int                            `json:"as_persona"`
	ContentSetRoles               []interface{}                  `json:"content_set_role_list"`
	CreationTime                  string                         `json:"creation_time"`
	Deleted                       bool                           `json:"deleted_flag"`
	DisplayName                   string                         `json:"display_name"`
	Domain                        string                         `json:"domain"`
	EffectiveContentSetPrivileges []EffectiveContentSetPrivilege `json:"effective_content_set_privileges"`
	EGID                          int                            `json:"effective_group_id"`
	GID                           int                            `json:"group_id"`
	LastLogin                     string                         `json:"last_login"`
	LocalAdmin                    int                            `json:"local_admin_flag"`
	LockedOut                     int                            `json:"locked_out"`
	Metadata                      []Metadata                     `json:"metadata"`
	ModificationTime              string                         `json:"modification_time"`
	ModPersona                    interface{}                    `json:"mod_persona"`
	ModUser                       interface{}                    `json:"mod_user"`
	OwnedObjects                  interface{}                    `json:"owned_object_ids"`
	Permissions                   []Permission                   `json:"permissions"`
	Personas                      []interface{}                  `json:"personas"`
	Roles                         []interface{}                  `json:"roles"`
	TrackComputerId               int                            `json:"track_computer_id_flag"`
	TrackComputerIdInterval       int                            `json:"track_computer_id_interval"`
}

type Group struct {
	And              bool     `json:"and_flag"`
	Deleted          bool     `json:"deleted_flag"`
	Filter           bool     `json:"filter_flag"`
	Filters          []Filter `json:"filters"`
	Id               int      `json:"id"`
	ManagementRights bool     `json:"management_rights_flag"`
	Not              bool     `json:"not_flag"`
	SubGroups        []Group  `json:"sub_groups"`
	Text             string   `json:"text"`
	Type             int      `json:"type"`
}

type QuestionDefinition struct {
	ActionTracking        bool        `json:"action_tracking_flag"`
	ContextGroup          Group       `json:"context_group"`
	Expiration            string      `json:"expiration"`
	ExpireSeconds         int         `json:"expire_seconds"`
	ForceComputerId       interface{} `json:"force_computer_id_flag"`
	FromCanonicalText     int         `json:"from_canonical_text"`
	Group                 Group       `json:"group"`
	Hidden                bool        `json:"hidden_flag"`
	Id                    int         `json:"id"`
	Index                 int         `json:"index"`
	IsExpired             bool        `json:"bool"`
	Persona               interface{} `json:"persona"`
	ManagementRightsGroup Group       `json:"management_rights_group"`
	QueryText             string      `json:"query_text"`
	QuestionText          string      `json:"question_text"`
	ParameterValues       []string    `json:"parameter_values"`
	SavedQuestion         Group       `json:"saved_question"`
	Selects               []Select    `json:"selects"`
	SensorReferences      []SensorRef `json:"sensor_references"`
	SkipLock              interface{} `json:"skip_lock_flag"`
	User                  Common      `json:"user"`
}

type Column struct {
	Hash int    `json:"hash"`
	Name string `json:"name"`
	Type int    `json:"type"`
}

type CellObj struct {
	Text string `json:"text"`
}

type Cell []CellObj

type Row struct {
	CId  int    `json:"cid"`
	Data []Cell `json:"data"`
	Id   int    `json:"id"`
}

// ResultSet is the Tanium ResultSet object
type ResultSet struct {
	Age                      int      `json:"age"`
	CacheId                  string   `json:"cache_id"`
	Columns                  []Column `json:"columns"`
	ArchivedQuestionId       int      `json:"archived_question_id"`
	ErrorCount               int      `json:"error_count"`
	EstimatedTotal           int      `json:"estimated_total"`
	Expiration               int      `json:"expiration"`
	ExpireSeconds            int      `json:"expire_seconds"`
	FilteredRowCount         int      `json:"filtered_row_count"`
	FilteredRowCountMachines int      `json:"filtered_row_count_machines"`
	Id                       int      `json:"id"`
	IssueSeconds             int      `json:"issue_seconds"`
	ItemCount                int      `json:"item_count"`
	MRPassed                 int      `json:"mr_passed"`
	MRTested                 int      `json:"mr_tested"`
	NoResultsCount           int      `json:"no_results_count"`
	Passed                   int      `json:"passed"`
	QuestionId               int      `json:"question_id"`
	ReportCount              int      `json:"report_count"`
	RowCount                 int      `json:"row_count"`
	RowCountMachines         int      `json:"row_count_machines"`
	Rows                     []Row    `json:"rows"`
	SavedQuestionId          int      `json:"saved_question_id"`
	SecondsSinceIssued       int      `json:"seconds_since_issued"`
	SelectCount              int      `json:"select_count"`
	Tested                   int      `json:"tested"`
}

type Question struct {
	QuestionDefinition
	client *TaniumClient
}

type APIToken struct {
	CreatedTime        string      `json:"created_time"`
	Deleted            int         `json:"deleted_flag"`
	Expiration         string      `json:"expiration"`
	ExpireInDays       int         `json:"expire_in_days"`
	Id                 int         `json:"id"`
	LastUsedOn         string      `json:"last_used_on"`
	Name               string      `json:"name"`
	Notes              string      `json:"notes"`
	Persona            interface{} `json:"persona"`
	Token              string      `json:"token_string"`
	TrustedIPAddresses string      `json:"trusted_ip_addresses"`
	User               User        `json:"user"`
}
