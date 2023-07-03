import pytest
from benedict import benedict

from rosa.cli import build_command, parse_help


@pytest.mark.parametrize(
    "cmd,aws_region",
    [
        pytest.param("whoami", "aws_region"),
        pytest.param("create cluster", "aws_region"),
        pytest.param("list clusters", "aws_region"),
        pytest.param("list oidc-config", "aws_region"),
        pytest.param("delete oidc-config", "aws_region"),
    ],
)
def test_json(cmd, aws_region):
    allowed_commands = parse_help()
    res = build_command(
        command=cmd, allowed_commands=allowed_commands, aws_region=aws_region
    )
    expected = benedict(allowed_commands, keypath_separator=" ")[cmd]
    if expected.get("json_output"):
        assert "-ojson" in res

    if expected.get("auto_answer_yes"):
        assert "--yes" in res

    if expected.get("auto_mode"):
        assert "--mode=auto" in res

    if expected.get("region") and aws_region:
        assert f"--region={aws_region}" in res
