import json
import re
import shlex
import subprocess

from simple_logger.logger import get_logger


LOGGER = get_logger(__name__)


def check_flag_in_flags(command_list, flag_str):
    available_flags = get_available_flags(command=command_list)
    for flag in available_flags:
        if flag_str in flag:
            return True
    return False


def get_available_commands(command):
    __available_commands = []
    command.append("--help")
    res = subprocess.run(command, capture_output=True, check=True, text=True)
    available_commands = re.findall(
        r"Available Commands:(.*)\nFlags:", res.stdout, re.DOTALL
    )
    if available_commands:
        available_commands = available_commands[0]
        available_commands = available_commands.strip()
        for _command in available_commands.splitlines():
            if _command:
                _command = _command.split()[0]
                _command = _command.strip()
                __available_commands.append(_command)
    return __available_commands


def get_available_flags(command):
    command.append("--help")
    available_flags = subprocess.run(
        command, capture_output=True, check=True, text=True
    )
    available_flags = re.findall(
        r"Flags:(.*)Global Flags:(.*)", available_flags.stdout, re.DOTALL
    )
    if available_flags:
        available_flags = " ".join([flags for flags in available_flags[0]])
        available_flags = available_flags.strip()
        return available_flags.splitlines()
    return []


def parse_help(rosa_cmd="rosa"):
    commands_dict = {}
    _commands = get_available_commands(command=[rosa_cmd])
    output_flag_str = "-o, --output"
    auto_answer_yes_str = "-y, --yes"
    auto_mode_str = "-m, --mode"
    billing_model_str = "--billing-model"

    for command in _commands:
        commands_dict.setdefault(command, {})

    for top_command in commands_dict.keys():
        _commands = get_available_commands(command=[rosa_cmd, top_command])
        for command in _commands:
            commands_dict[top_command][command] = {}
            _commands = get_available_commands(command=[rosa_cmd, top_command, command])
            if _commands:
                for _command in _commands:
                    commands_dict[top_command][command][_command] = {}
                    commands_dict[top_command][command][_command][
                        "json_output"
                    ] = check_flag_in_flags(
                        command_list=[rosa_cmd, top_command, _command],
                        flag_str=output_flag_str,
                    )
                    commands_dict[top_command][command][_command][
                        "auto_answer_yes"
                    ] = check_flag_in_flags(
                        command_list=[rosa_cmd, top_command, _command],
                        flag_str=auto_answer_yes_str,
                    )
                    commands_dict[top_command][command][_command][
                        "auto_mode"
                    ] = check_flag_in_flags(
                        command_list=[rosa_cmd, top_command, _command],
                        flag_str=auto_mode_str,
                    )
                    commands_dict[top_command][command][_command][
                        "billing_model"
                    ] = check_flag_in_flags(
                        command_list=[rosa_cmd, top_command, _command],
                        flag_str=billing_model_str,
                    )
            else:
                commands_dict[top_command][command][
                    "json_output"
                ] = check_flag_in_flags(
                    command_list=[rosa_cmd, top_command, command],
                    flag_str=output_flag_str,
                )
                commands_dict[top_command][command][
                    "auto_answer_yes"
                ] = check_flag_in_flags(
                    command_list=[rosa_cmd, top_command, command],
                    flag_str=auto_answer_yes_str,
                )
                commands_dict[top_command][command]["auto_mode"] = check_flag_in_flags(
                    command_list=[rosa_cmd, top_command, command],
                    flag_str=auto_mode_str,
                )
                commands_dict[top_command][command][
                    "billing_model"
                ] = check_flag_in_flags(
                    command_list=[rosa_cmd, top_command, command],
                    flag_str=billing_model_str,
                )

    return commands_dict


def parse_json_response(response):
    try:
        return json.loads(response)
    except json.decoder.JSONDecodeError:
        return response.splitlines()


def execute(command, allowed_commands=None, billing_model_value="standard"):
    """
    Support commands and execute with ROSA cli

    Args:
        command (str): ROSA cli command to execute
        allowed_commands (dict): Commands dict of dicts with following
            options for each entry
            Example:
                {'create':
                    {'account-roles': {'json_output': False, 'auto_answer_yes': True,
                        'auto_mode': True, 'billing_model': False},
                    'admin': {'json_output': True, 'auto_answer_yes': True, 'auto_mode': False, 'billing_model': False},
                    'cluster': {'json_output': True, 'auto_answer_yes': True, 'auto_mode': True, 'billing_model': False}
                    }}
        billing_model_value (str): If needed, set the billing model to be used for some
            operations. Default value is "standard".


    Returns:
        list or json: json if json.loads(res.stdout) not fail, else list of output after 'splitlines'.

    Raise:
        If billing model is invalid
    """
    billing_options = [
        "marketplace",
        "standard",
        "marketplace-aws",
        "marketplace-azure",
        "marketplace-rhm",
    ]
    if billing_model_value not in billing_options:
        raise LOGGER.error(
            f"The billing model mentioned is not valid, must be one of the followings:\n{billing_options}"
        )
    allowed_commands = allowed_commands or parse_help()
    _user_command = shlex.split(command)
    command = ["rosa"]
    command.extend(_user_command)
    json_output = {}
    auto_answer_yes = {}
    auto_update = {}
    billing_model = {}
    for cmd in command[1:]:
        if cmd.startswith("--"):
            continue

        json_output = allowed_commands.get(cmd, json_output.get(cmd, {}))
        add_json_output = json_output.get("json_output") is True
        if add_json_output:
            command.append("-ojson")

        auto_answer_yes = allowed_commands.get(cmd, auto_answer_yes.get(cmd, {}))
        add_auto_answer_yes = auto_answer_yes.get("auto_answer_yes") is True
        if add_auto_answer_yes:
            command.append("--yes")

        auto_update = allowed_commands.get(cmd, auto_update.get(cmd, {}))
        add_auto_update = auto_update.get("auto_mode") is True
        if add_auto_update:
            command.append("--mode=auto")

        # TODO remove support for billing-model flag once https://github.com/openshift/rosa/issues/1279 resolved
        billing_model = allowed_commands.get(cmd, billing_model.get(cmd, {}))
        add_billing_model = billing_model.get("billing_model") is True
        if add_billing_model:
            command.append(f"--billing-model {billing_model_value}")

        if any(
            [add_json_output, add_auto_answer_yes, add_auto_update, add_billing_model]
        ):
            break

    LOGGER.info(f"Executing command: {' '.join(command)}")
    res = subprocess.run(command, capture_output=True, check=True, text=True)
    return parse_json_response(response=res.stdout)
