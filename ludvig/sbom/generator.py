import enum
from cyclonedx.output import (
    BaseOutput,
    OutputFormat,
    SchemaVersion,
    get_instance as get_output_instance,
)


@enum.unique
class _CLI_OUTPUT_FORMAT(enum.Enum):
    XML = "xml"
    JSON = "json"


_output_formats = {
    _CLI_OUTPUT_FORMAT.XML: OutputFormat.XML,
    _CLI_OUTPUT_FORMAT.JSON: OutputFormat.JSON,
}
_output_default_filenames = {
    _CLI_OUTPUT_FORMAT.XML: "cyclonedx.xml",
    _CLI_OUTPUT_FORMAT.JSON: "cyclonedx.json",
}
