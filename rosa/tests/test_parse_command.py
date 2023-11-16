import pytest
from benedict import benedict
from simple_logger.logger import get_logger

from rosa.cli import build_command, parse_help
from rosa.tests.const import AWS_REGION_STR


LOGGER = get_logger(name=__name__)


@pytest.fixture()
def rosa_commands(request):
    return request.param


def test_json(rosa_commands):
    allowed_commands = parse_help()
    command = rosa_commands["command"]
    aws_region = rosa_commands[AWS_REGION_STR]
    rosa_command = build_command(command=command, allowed_commands=allowed_commands, aws_region=aws_region)
    expected = benedict(allowed_commands, keypath_separator=" ")[command]
    LOGGER.info(f"Processing command: {' '.join(rosa_command)}")

    if expected.get("json_output"):
        assert "-ojson" in rosa_command

    if expected.get("auto_answer_yes"):
        assert "--yes" in rosa_command

    if expected.get("auto_mode"):
        assert "--mode=auto" in rosa_command

    if expected.get("region") and aws_region:
        assert f"--region={aws_region}" in rosa_command
