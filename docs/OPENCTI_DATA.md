# OpenCTI Data

OpenCTI stores its data in Elastic. The Elastic schema for implementing the different types of objects required by OpenCTI looks as follows:

```mermaid
classDiagram
  class opencti {
    <<DOCUMENT>>
    UUID|NON_SENSITIVE applicant_id
    ENUM|NON_SENSITIVE base_type
    INTEGER|NON_SENSITIVE completed_number
    TIMESTAMP|NON_SENSITIVE completed_time
    UUID|NON_SENSITIVE connector_id
    ENUM|NON_SENSITIVE context_data.entity_type
    UUID|NON_SENSITIVE context_data.from_id
    UUID|NON_SENSITIVE context_data.id
    STRING|SENSITIVE context_data.message
    UUID|NON_SENSITIVE context_data.to_id
    TIMESTAMP|NON_SENSITIVE created_at
    ENUM|NON_SENSITIVE entity_type
    UUID|NON_SENSITIVE event_source_id
    ENUM|NON_SENSITIVE event_type
    UUID|NON_SENSITIVE id
    STRING|NON_SENSITIVE internal_id
    STRING|NON_SENSITIVE messages.message
    TIMESTAMP|NON_SENSITIVE messages.timestamp
    STRING|NON_SENSITIVE name
    ENUM|NON_SENSITIVE parent_types
    TIMESTAMP|NON_SENSITIVE processed_time
    TIMESTAMP|NON_SENSITIVE received_time
    UUID|NON_SENSITIVE rel_migrates.internal_id
    STRING|NON_SENSITIVE standard_id
    ENUM|NON_SENSITIVE status
    TIMESTAMP|NON_SENSITIVE timestamp
    STRING|NON_SENSITIVE title
    TIMESTAMP|NON_SENSITIVE updated_at
    UUID|PII_EMPLOYEE user_id
  }
```

OpenCTI implements the STIX standard for representing threat intelligence. It does this by implementing schema for two different types of objects: entities and relations. Entities are things like organizations, malware, and events. Relations are connects between any two entities. For example, there may be an IP address entity and a domain name entity with a relation describing how the domain name resolves to the IP, which defines three objects in the database.

The following entity and relation schemas come from the [Luatix documentation](https://luatix.notion.site/Data-model-4427344d93a74fe194d5a52ce4a41a8d) for the public [OpenCTI project](https://github.com/OpenCTI-Platform/opencti).

![Entity](./diagrams/opencti_model_entities.png)

![Relation](./diagrams/opencti_model_relations.png)

