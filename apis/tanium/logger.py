import logging
import ecs_logging

EXCLUDE_FIELDS = ["origin", "process", "log", "ecs"]


class AppSecFormatter(ecs_logging.StdlibFormatter):
    def __init__(
        self,
        service_name,
        environment,
        tags,
        cloud_account_id,
        cloud_instance_id,
        cloud_instance_name=None,
        default_event=None,
    ):
        self.service_name = service_name
        self.environment = environment
        self.tags = list(set(["security"] + tags))
        self.cloud_account_id = cloud_account_id
        self.cloud_instance_id = cloud_instance_id
        self.cloud_instance_name = cloud_instance_name
        self.default_event = default_event
        self.current_event = None
        super().__init__(exclude_fields=EXCLUDE_FIELDS)

    def set_default_event(self, default_event):
        self.default_event = default_event

    def set_event(self, current_event):
        self.current_event = current_event

    def reset_event(self):
        self.current_event = None

    def format_to_ecs(self, record):
        result = super().format_to_ecs(record)
        result["labels"] = {"environment": self.environment}
        result["tags"] = self.tags
        if self.cloud_account_id is not None:
            result["cloud"] = {
                "account": {"id": self.cloud_account_id},
                "instance": {"id": self.cloud_instance_id},
            }
            if self.cloud_instance_name is not None:
                result["cloud"]["instance"]["name"] = self.cloud_instance_name
        if self.current_event is None and self.default_event is not None:
            result["event"] = self.default_event.to_dict()
        elif self.current_event is not None:
            result["event"] = self.current_event.to_dict()
            self.reset_event()
        result["service"] = {"name": self.service_name}
        return result


class AppSecLogger(logging.Logger):
    def event(self, current_event):
        """
        This is a convenience method that temporarily sets the event in the embedded formatter(s).
        """
        appsecformatters = list(
            map(
                lambda x: x.formatter,
                filter(
                    lambda x: isinstance(x.formatter, AppSecFormatter), self.handlers
                ),
            )
        )
        for appsecformatter in appsecformatters:
            appsecformatter.set_event(current_event)
        return self
