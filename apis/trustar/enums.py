import enum

"""
https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-kind.html
"""
class EventKind(enum.Enum):
    alert = 'alert'
    event = 'event'
    metric = 'metric'
    state = 'state'
    pipeline_error = 'pipeline_error'
    signal = 'signal'

"""
https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-category.html
"""
class EventCategory(enum.Enum):
    authentication = 'authentication'
    configuration = 'configuration'
    database = 'database'
    driver = 'driver'
    file = 'file'
    host = 'host'
    iam = 'iam'
    intrusion_detection = 'intrusion_detection'
    malware = 'malware'
    network = 'network'
    package = 'package'
    process = 'process'
    web = 'web'

"""
https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-type.html
"""
class EventType(enum.Enum):
    access = 'access'
    admin = 'admin'
    allowed = 'allowed'
    change = 'change'
    connection = 'connection'
    creation = 'creation'
    deletion = 'deletion'
    denied = 'denied'
    end = 'end'
    error = 'error'
    group = 'group'
    info = 'info'
    installation = 'installation'
    protocol = 'protocol'
    start = 'start'
    user = 'user'

"""
https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-outcome.html
"""
class EventOutcome(enum.Enum):
    success = 'success'
    failure = 'failure'
    unknown = 'unknown'
