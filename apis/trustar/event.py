class Event(object):
    def __init__(self, event_kind, event_category, event_type, event_outcome=None):
        self.event_kind = event_kind
        self.event_category = event_category
        self.event_type = event_type
        self.event_outcome = event_outcome

    def to_dict(self):
        return {
            'kind': self.event_kind.value,
            'category': self.event_category.value,
            'type': self.event_type.value
        }