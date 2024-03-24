import contextlib
import functools
import json
import os
import re
import shlex
import subprocess

from benedict import benedict
from clouds.aws.aws_utils import set_and_verify_aws_credentials
from ocm_python_wrapper.ocm_client import OCMPythonClient
from simple_logger.logger import get_logger


LOGGER = get_logger(name=__name__)
TIMEOUT_5MIN = 5 * 60


class MissingAWSCredentials(Exception):
    pass


class CommandExecuteError(Exception):
    pass


class NotLoggedInOrWrongEnvError(Exception):
    pass


def hash_log_keys(log):
    for _key in (
        "token",
        "worker-iam-role",
        "support-role-arn",
        "role-arn",
        "controlplane-iam-role",
        "kms-key-arn",
        "etcd-encryption-kms-arn",
        "audit-log-arn",
        "base-domain",
        "installer-role-arn",
        "billing-account",
    ):
        log = re.sub(rf"(--{_key}=[^\s]+)", f"--{_key}={'*' * 5} ", log)

    return log


def rosa_login(env, token, aws_region, allowed_commands=None):
    _allowed_commands = allowed_commands or parse_help()

    try:
        is_logged_in(allowed_commands=_allowed_commands, aws_region=aws_region, env=env)
        LOGGER.info(f"Already logged in to {env} [region: {aws_region}].")
        return

    except NotLoggedInOrWrongEnvError:
        build_execute_command(
            command=f"login --env={env} --token={token}",
            allowed_commands=_allowed_commands,
        )
        is_logged_in(allowed_commands=_allowed_commands, aws_region=aws_region, env=env)


def rosa_logout(allowed_commands=None):
    _allowed_commands = allowed_commands or parse_help()
    build_execute_command(command="logout", allowed_commands=_allowed_commands)


@contextlib.contextmanager
def change_home_environment():
    current_home = os.environ.get("HOME")
    os.environ["HOME"] = "/tmp/"
    yield
    os.environ["HOME"] = current_home


def is_logged_in(env, aws_region=None, allowed_commands=None):
    _allowed_commands = allowed_commands or parse_help()

    try:
        res = build_execute_command(command="whoami", aws_region=aws_region, allowed_commands=_allowed_commands)

        if _err := res.get("err"):
            raise NotLoggedInOrWrongEnvError(f"Failed to execute 'rosa whoami': {_err}")

        if not isinstance(res["out"], dict):
            raise NotLoggedInOrWrongEnvError(f"Rosa `out` is not a dict': {res['out']}")

        logged_in_ocm_env = res["out"].get("OCM API")
        if logged_in_ocm_env != env:
            raise NotLoggedInOrWrongEnvError(
                f"User is logged in to OCM in {logged_in_ocm_env} environment and not {env} environment."
            )

    except CommandExecuteError as ex:
        raise NotLoggedInOrWrongEnvError(f"Failed to execute 'rosa whoami': {ex}")


def execute_command(command, wait_timeout=TIMEOUT_5MIN):
    log = f"Executing command: {' '.join(command)}, waiting for {wait_timeout} seconds."
    hashed_log = hash_log_keys(log=log)
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
    LOGGER.info(hash_log_keys(log=f"Parsing user command: {command}"))
    _allowed_commands = allowed_commands or parse_help()
    _user_command = shlex.split(command)
    command = ["rosa"]
    command.extend(_user_command)
    commands_to_process = [_cmd for _cmd in _user_command if not _cmd.startswith(("--", "-"))]
    commands_dict = benedict(_allowed_commands, keypath_separator=" ")
    commands_to_process_len = len(commands_to_process)
    extra_commands = set()
    for idx in range(commands_to_process_len):
        try:
            _output = commands_dict[commands_to_process[: commands_to_process_len - idx]]
        except KeyError:
            continue
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
    command = update_command(command=command)
    res = subprocess.run(command, capture_output=True, check=True, text=True)
    available_commands = re.findall(r"Available Commands:(.*)\nFlags:", res.stdout, re.DOTALL)
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
    command = update_command(command=command)
    available_flags = subprocess.run(command, capture_output=True, check=True, text=True)
    available_flags = re.findall(r"Flags:(.*)Global Flags:(.*)", available_flags.stdout, re.DOTALL)
    if available_flags:
        available_flags = " ".join([flags for flags in available_flags[0]])
        available_flags = available_flags.strip()
        return available_flags.splitlines()
    return []


@functools.cache
def parse_help():
    def _fill_commands_dict_with_support_flags(commands_dict, flag_key_path):
        support_commands = {
            "json_output": "-o, --output",
            "auto_answer_yes": "-y, --yes",
            "auto_mode": "-m, --mode",
            "region": "--region",
        }
        for cli_flag, flag_value in support_commands.items():
            commands_dict[flag_key_path][cli_flag] = check_flag_in_flags(
                command_list=["rosa"] + flag_key_path,
                flag_str=flag_value,
            )
        return commands_dict

    def _build_command_tree(commands_dict, commands_search_path=None):
        if not commands_search_path:
            commands_search_path = []

        sub_commands = get_available_commands(command=["rosa"] + commands_search_path)
        for sub_command in sub_commands:
            commands_dict[commands_search_path, sub_command] = {}
            commands_dict = _fill_commands_dict_with_support_flags(
                commands_dict=commands_dict,
                flag_key_path=commands_search_path + [sub_command],
            )
            _build_command_tree(
                commands_dict=commands_dict,
                commands_search_path=commands_search_path + [sub_command],
            )

        return commands_dict

    return _build_command_tree(commands_dict=benedict())


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
    command = build_command(command=command, allowed_commands=_allowed_commands, aws_region=aws_region)
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

        else:
            ocm_env = OCMPythonClient.get_base_api_uri(api_host=ocm_env)

        # If running on openshift-ci we need to change $HOME to /tmp
        if os.environ.get("OPENSHIFT_CI") == "true":
            LOGGER.info("Running in openshift ci")
            with change_home_environment():
                return _prepare_and_execute_command(
                    allowed_commands=_allowed_commands,
                    aws_region=aws_region,
                    command=command,
                    ocm_env=ocm_env,
                    token=token,
                )
        else:
            return _prepare_and_execute_command(
                allowed_commands=_allowed_commands,
                aws_region=aws_region,
                command=command,
                ocm_env=ocm_env,
                token=token,
            )

    else:
        is_logged_in(allowed_commands=_allowed_commands, aws_region=aws_region, env=ocm_env)

        return build_execute_command(command=command, allowed_commands=_allowed_commands, aws_region=aws_region)


def _prepare_and_execute_command(allowed_commands, aws_region, command, ocm_env, token):
    set_and_verify_aws_credentials(region_name=aws_region)
    rosa_login(
        env=ocm_env,
        token=token,
        aws_region=aws_region,
        allowed_commands=allowed_commands,
    )
    return build_execute_command(
        command=command,
        allowed_commands=allowed_commands,
        aws_region=aws_region,
    )


def update_command(command):
    # Addon ID is needed until https://github.com/openshift/rosa/issues/1835 is resolved
    if "rosa edit addon" in " ".join(command):
        command.append("addon_name")

    command.append("--help")

    return command


if __name__ == "__main__":
    """
    for local debugging.
    """
