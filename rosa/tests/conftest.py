from rosa.cli import parse_help
from rosa.tests.const import AWS_REGION_STR


def path_from_dict(_dict=None, _path=""):
    end_values = ["json_output", "auto_answer_yes", "auto_mode", "region"]

    for key, val in _dict.items():
        # If dict == end_values we need to test it
        if isinstance(val, dict):
            if all([_key in end_values for _key in val.keys()]):
                yield {
                    "command": f"{_path}{key}",
                    AWS_REGION_STR: AWS_REGION_STR if val["region"] else None,
                }
            yield from path_from_dict(_dict=val, _path=f"{key} ")


def pytest_generate_tests(metafunc):
    if "rosa_commands" in metafunc.fixturenames:
        parametrized = list(path_from_dict(_dict=parse_help()))
        metafunc.parametrize("rosa_commands", parametrized, indirect=True)
