import contextlib
import functools
import json
import os
import re
import shlex
import subprocess

from benedict import benedict
from clouds.aws.aws_utils import set_and_verify_aws_credentials
from simple_logger.logger import get_logger


LOGGER = get_logger(__name__)
TIMEOUT_5MIN = 5 * 60


class MissingAWSCredentials(Exception):
    pass


class CommandExecuteError(Exception):
    pass


class NotLoggedInError(Exception):
    pass


def hash_log_secrets(log, secrets):
    for secret in secrets:
        log = re.sub(
            rf"(--{secret}=.* |--{secret}=.*)", f"--{secret}=hashed-{secret} ", log
        )

    return log


def rosa_login(env, token, aws_region, allowed_commands=None):
    _allowed_commands = allowed_commands or parse_help()
    build_execute_command(
        command=f"login {f'--env={env}' if env else ''} --token={token}",
        allowed_commands=_allowed_commands,
        aws_region=aws_region,
    )
    if not is_logged_in(allowed_commands=_allowed_commands, aws_region=aws_region):
        raise NotLoggedInError("Failed to login to AWS.")


def rosa_logout(allowed_commands=None):
    _allowed_commands = allowed_commands or parse_help()
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


def execute_command(command, wait_timeout=TIMEOUT_5MIN):
    log = f"Executing command: {' '.join(command)}, waiting for {wait_timeout} seconds."
    hashed_log = hash_log_secrets(log=log, secrets=["token"])
    LOGGER.info(hashed_log)
    res = subprocess.run(command, capture_output=True, text=True, timeout=wait_timeout)
    if res.returncode != 0:
        raise CommandExecuteError(f"Failed to execute '{hashed_log}': {res.stderr}")

    return parse_json_response(response=res)


def check_flag_in_flags(command_list, flag_str):
    available_flags = get_available_flags(command=command_list)
    for flag in available_flags:
        if flag_str in flag:
            return True
    return False


def build_command(command, allowed_commands=None, aws_region=None):
    LOGGER.info(
        hash_log_secrets(log=f"Parsing user command: {command}", secrets=["token"])
    )
    _allowed_commands = allowed_commands or parse_help()
    _user_command = shlex.split(command)
    command = ["rosa"]
    command.extend(_user_command)
    commands_to_process = [
        _cmd for _cmd in _user_command if not _cmd.startswith(("--", "-"))
    ]
    commands_dict = benedict(_allowed_commands, keypath_separator=" ")
    commands_to_process_len = len(commands_to_process)
    extra_commands = set()
    for idx in range(commands_to_process_len):
        _output = commands_dict[commands_to_process[: commands_to_process_len - idx]]
        if _output.get("json_output") is True:
            extra_commands.add("-ojson")

        if _output.get("auto_answer_yes") is True:
            extra_commands.add("--yes")

        if _output.get("auto_mode") is True:
            extra_commands.add("--mode=auto")

        if _output.get("region") is True and aws_region:
            extra_commands.add(f"--region={aws_region}")

    command.extend(extra_commands)
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
        # Always get top commands options
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

        _commands = get_available_commands(command=[rosa_cmd, top_command])

        if _commands:
            for command in _commands:
                commands_dict[top_command][command] = {}
                # Always get sub commands options
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
                commands_dict[top_command][command]["region"] = check_flag_in_flags(
                    command_list=[rosa_cmd, top_command, command],
                    flag_str=region_str,
                )

                _commands = get_available_commands(
                    command=[rosa_cmd, top_command, command]
                )

                # If top command has sub command
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
        set_and_verify_aws_credentials(region_name=aws_region)

        if ocm_client:
            ocm_env = ocm_client.api_client.configuration.host
            token = ocm_client.api_client.token

        rosa_login(
            env=ocm_env,
            token=token,
            aws_region=aws_region,
            allowed_commands=_allowed_commands,
        )

        # If running on openshift-ci we need to change $HOME to /tmp
        if os.environ.get("OPENSHIFT_CI") == "true":
            with change_home_environment():
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


if __name__ == "__main__":
    """
    for local debugging.
    """
