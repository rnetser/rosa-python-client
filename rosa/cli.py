import contextlib
import functools
import json
import os
import re
import shlex
import subprocess

from clouds.aws.aws_utils import verify_aws_credentials
from simple_logger.logger import get_logger


LOGGER = get_logger(__name__)


class CommandExecuteError(Exception):
    pass


class NotLoggedInError(Exception):
    pass


@contextlib.contextmanager
def rosa_login_logout(env, token, aws_region, allowed_commands=None):
    verify_aws_credentials()
    _allowed_commands = allowed_commands or parse_help()
    build_execute_command(
        command=f"login {f'--env={env}' if env else ''} --token={token}",
        allowed_commands=_allowed_commands,
        aws_region=aws_region,
    )
    if not is_logged_in(allowed_commands=_allowed_commands, aws_region=aws_region):
        raise NotLoggedInError("Failed to login to AWS.")

    yield
    build_execute_command(command="logout", allowed_commands=_allowed_commands)


@contextlib.contextmanager
def change_home_environment():
    current_home = os.environ.get("HOME")
    os.environ["HOME"] = "/tmp/"
    yield
    os.environ["HOME"] = current_home


def is_logged_in(aws_region=None, allowed_commands=None):
    _allowed_commands = allowed_commands or parse_help()
    try:
        res = build_execute_command(
            command="whoami", aws_region=aws_region, allowed_commands=_allowed_commands
        )
        return "User is not logged in to OCM" not in res["err"]
    except CommandExecuteError:
        return False


def execute_command(command):
    joined_command = " ".join(command)
    LOGGER.info(
        f"Executing command: {re.sub(r'(--token=.* |--token=.*)', '--token=hashed-token ', joined_command)}"
    )
    res = subprocess.run(command, capture_output=True, text=True)
    if res.returncode != 0:
        raise CommandExecuteError(f"Failed to execute: {res.stderr}")

    return parse_json_response(response=res)


def check_flag_in_flags(command_list, flag_str):
    available_flags = get_available_flags(command=command_list)
    for flag in available_flags:
        if flag_str in flag:
            return True
    return False


def build_command(command, allowed_commands=None, aws_region=None):
    _allowed_commands = allowed_commands or parse_help()
    _user_command = shlex.split(command)
    command = ["rosa"]
    command.extend(_user_command)
    json_output = {}
    auto_answer_yes = {}
    auto_update = {}
    aws_region_flag = {}
    for cmd in command[1:]:
        if cmd.startswith("--"):
            continue

        json_output = _allowed_commands.get(cmd, json_output.get(cmd, {}))
        add_json_output = json_output.get("json_output") is True
        if add_json_output:
            command.append("-ojson")

        auto_answer_yes = _allowed_commands.get(cmd, auto_answer_yes.get(cmd, {}))
        add_auto_answer_yes = auto_answer_yes.get("auto_answer_yes") is True
        if add_auto_answer_yes:
            command.append("--yes")

        auto_update = _allowed_commands.get(cmd, auto_update.get(cmd, {}))
        add_auto_update = auto_update.get("auto_mode") is True
        if add_auto_update:
            command.append("--mode=auto")

        aws_region_flag = _allowed_commands.get(cmd, aws_region_flag.get(cmd, {}))
        add_aws_region_flag = json_output.get("region") is True
        if add_aws_region_flag and aws_region:
            command.append(f"--region={aws_region}")

        if any(
            [add_json_output, add_auto_answer_yes, add_auto_update, add_aws_region_flag]
        ):
            break

    return command


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


@functools.cache
def parse_help(rosa_cmd="rosa"):
    commands_dict = {}
    _commands = get_available_commands(command=[rosa_cmd])
    output_flag_str = "-o, --output"
    auto_answer_yes_str = "-y, --yes"
    auto_mode_str = "-m, --mode"
    region_str = "--region"

    for command in _commands:
        commands_dict.setdefault(command, {})

    for top_command in commands_dict.keys():
        _commands = get_available_commands(command=[rosa_cmd, top_command])

        if _commands:
            # If top command has sub command
            for command in _commands:
                commands_dict[top_command][command] = {}
                _commands = get_available_commands(
                    command=[rosa_cmd, top_command, command]
                )
                if _commands:
                    # If sub command has sub command
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
                            "region"
                        ] = check_flag_in_flags(
                            command_list=[rosa_cmd, top_command, _command],
                            flag_str=region_str,
                        )
                else:
                    # If sub command doesn't have sub command
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
                    commands_dict[top_command][command][
                        "auto_mode"
                    ] = check_flag_in_flags(
                        command_list=[rosa_cmd, top_command, command],
                        flag_str=auto_mode_str,
                    )
                    commands_dict[top_command][command]["region"] = check_flag_in_flags(
                        command_list=[rosa_cmd, top_command, command],
                        flag_str=region_str,
                    )

        else:
            # If top command doesn't have sub command
            commands_dict[top_command]["json_output"] = check_flag_in_flags(
                command_list=[rosa_cmd, top_command],
                flag_str=output_flag_str,
            )
            commands_dict[top_command]["auto_answer_yes"] = check_flag_in_flags(
                command_list=[rosa_cmd, top_command],
                flag_str=auto_answer_yes_str,
            )
            commands_dict[top_command]["auto_mode"] = check_flag_in_flags(
                command_list=[rosa_cmd, top_command],
                flag_str=auto_mode_str,
            )
            commands_dict[top_command]["region"] = check_flag_in_flags(
                command_list=[rosa_cmd, top_command],
                flag_str=region_str,
            )

    return commands_dict


def parse_json_response(response):
    def _try_json_load(arg):
        try:
            return json.loads(arg)
        except json.decoder.JSONDecodeError:
            return arg

    return {
        "out": _try_json_load(response.stdout),
        "err": _try_json_load(response.stderr),
    }


def build_execute_command(command, allowed_commands=None, aws_region=None):
    _allowed_commands = allowed_commands or parse_help()
    command = build_command(
        command=command, allowed_commands=_allowed_commands, aws_region=aws_region
    )
    return execute_command(command=command)


def execute(
    command,
    allowed_commands=None,
    ocm_env="production",
    token=None,
    ocm_client=None,
    aws_region=None,
):
    """
    Support commands and execute with ROSA cli

    If 'token' or 'ocm_client' is passed, log in to rosa execute the command and then logout.

    Args:
        command (str): ROSA cli command to execute.
        allowed_commands (dict): Commands dict of dicts with following
            options for each entry.
        ocm_env (str): OCM env to log in into.
        token (str): Access or refresh token generated from https://console.redhat.com/openshift/token/rosa.
        ocm_client (OCMPythonClient): OCM client to use for log in.
        aws_region (str): AWS region to use for ROSA commands.

    Example:
        allowed_commands = {'create':
            {'account-roles': {'json_output': False, 'auto_answer_yes': True,
                'auto_mode': True, 'billing_model': False},
            'admin': {'json_output': True, 'auto_answer_yes': True, 'auto_mode': False, 'billing_model': False},
            'cluster': {'json_output': True, 'auto_answer_yes': True, 'auto_mode': True, 'billing_model': False}
            }}

    Returns:
        dict: {'out': res.stdout, 'err': res.stderr}
            res.stdout/stderr will be parsed as json if possible, else str
    """
    _allowed_commands = allowed_commands or parse_help()

    if token or ocm_client:
        if ocm_client:
            ocm_env = ocm_client.api_client.configuration.host
            token = ocm_client.api_client.token

        with change_home_environment(), rosa_login_logout(
            env=ocm_env,
            token=token,
            aws_region=aws_region,
            allowed_commands=_allowed_commands,
        ):
            return build_execute_command(
                command=command,
                allowed_commands=_allowed_commands,
                aws_region=aws_region,
            )

    else:
        if not is_logged_in(allowed_commands=_allowed_commands, aws_region=aws_region):
            raise NotLoggedInError(
                "Not logged in to OCM, either pass 'token' or log in before running."
            )

        return build_execute_command(
            command=command, allowed_commands=_allowed_commands, aws_region=aws_region
        )
