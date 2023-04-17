import json
import re
import subprocess


def output_in_flags(command):
    available_flags = get_available_flags(command=command)
    for flag in available_flags:
        if "-o, --output" in flag:
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
        r"Flags:(.*)Global Flags:", available_flags.stdout, re.DOTALL
    )
    if available_flags:
        available_flags = available_flags[0]
        available_flags = available_flags.strip()
        return available_flags.splitlines()
    return []


def parse_help(rosa_cmd="rosa"):
    commands_dict = {}
    _commands = get_available_commands(command=[rosa_cmd])
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
                    ] = output_in_flags([rosa_cmd, top_command, _command])
            else:
                commands_dict[top_command][command]["json_output"] = output_in_flags(
                    [rosa_cmd, top_command, command]
                )

    return commands_dict


def parse_json_response(response: str) -> list or json:
    try:
        return json.loads(response)
    except json.decoder.JSONDecodeError:
        return response.splitlines()


def execute(user_command, allowed_commands=None):
    allowed_commands = allowed_commands or parse_help()
    _user_command = user_command.split(" ")
    command = ["rosa"]
    command.extend(_user_command)
    json_output = None
    for cmd in command[1:]:
        json_output = allowed_commands[cmd] if not json_output else json_output[cmd]

    if json_output:
        command.append("-ojson")

    res = subprocess.run(command, capture_output=True, check=True, text=True)
    return parse_json_response(response=res.stdout)
