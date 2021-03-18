package appseclogging

type EventKind string
type EventCategory string
type EventType string
type EventOutcome string

const (
	// Event Kinds

	EventKindAlert         EventKind = "alert"
	EventKindEvent         EventKind = "event"
	EventKindMetric        EventKind = "metric"
	EventKindState         EventKind = "state"
	EventKindPipelineError EventKind = "pipeline_error"
	EventKindSignal        EventKind = "signal"

	// Event Categories

	EventCategoryAuthentication     EventCategory = "authentication"
	EventCategoryConfiguration      EventCategory = "configuration"
	EventCategoryDatabase           EventCategory = "database"
	EventCategoryDriver             EventCategory = "driver"
	EventCategoryFile               EventCategory = "file"
	EventCategoryHost               EventCategory = "host"
	EventCategoryIam                EventCategory = "iam"
	EventCategoryIntrusionDetection EventCategory = "intrusion_detection"
	EventCategoryMalware            EventCategory = "malware"
	EventCategoryNetwork            EventCategory = "network"
	EventCategoryPackage            EventCategory = "package"
	EventCategoryProcess            EventCategory = "process"
	EventCategoryWeb                EventCategory = "web"

	// Event Types

	EventTypeAccess       EventType = "access"
	EventTypeAdmin        EventType = "admin"
	EventTypeAllowed      EventType = "allowed"
	EventTypeChange       EventType = "change"
	EventTypeConnection   EventType = "connection"
	EventTypeCreation     EventType = "creation"
	EventTypeDeletion     EventType = "deletion"
	EventTypeDenied       EventType = "denied"
	EventTypeEnd          EventType = "end"
	EventTypeError        EventType = "error"
	EventTypeGroup        EventType = "group"
	EventTypeInfo         EventType = "info"
	EventTypeInstallation EventType = "installation"
	EventTypeProtocol     EventType = "protocol"
	EventTypeStart        EventType = "start"
	EventTypeUser         EventType = "user"

	// Event Outcomes

	EventOutcomeSuccess EventOutcome = "success"
	EventOutcomeFailure EventOutcome = "failure"
	EventOutcomeUnknown EventOutcome = "unknown"
)

type Event struct {
	EventKind     string
	EventCategory string
	EventType     string
	EventOutcome  string
}
