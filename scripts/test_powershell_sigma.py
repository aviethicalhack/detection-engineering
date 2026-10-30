
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "datasets" / "powershell_test_events.json"



def matches_rule(event):
    image = event.get("Image", "").lower()
    command_line = event.get("CommandLine", "").lower()

    is_powershell = image.endswith(
        ("\\powershell.exe", "\\pwsh.exe")
    )

    if not is_powershell:
        return False

    # Split the command line into individual arguments.
    import shlex
    import re

    try:
        arguments = shlex.split(command_line, posix=False)
    except ValueError:
        arguments = command_line.split()

    # Match encoded-command options, including valid abbreviations.
    has_encoded_indicator = any(
        re.fullmatch(r"-enc(?:odedcom(?:mand)?)?", arg.strip('"'))
        for arg in arguments
    )

    # Match specific execution-evasion options.
    normalized_arguments = [
        arg.strip('"').lower() for arg in arguments
    ]

    has_evasion_indicator = any(
        arg in (
            "-nop",
            "-noprofile",
            "-executionpolicy",
            "-windowstyle",
        )
        for arg in normalized_arguments
    )

    # Check the values of options that require a following argument.
    for index, arg in enumerate(normalized_arguments[:-1]):
        next_arg = normalized_arguments[index + 1].strip('"')

        if arg == "-executionpolicy" and next_arg == "bypass":
            has_evasion_indicator = True

        if arg == "-windowstyle" and next_arg == "hidden":
            has_evasion_indicator = True

    return has_encoded_indicator or has_evasion_indicator



def main():
    with DATASET.open("r", encoding="utf-8") as file:
        events = json.load(file)

    passed = 0

    for event in events:
        actual = matches_rule(event)
        expected = event["expected_match"]
        success = actual == expected

        if success:
            passed += 1

        status = "PASS" if success else "FAIL"
        print(
            f"{status} | {event['test_id']} | "
            f"Expected={expected}, Actual={actual} | "
            f"{event['description']}"
        )

    print(f"\nResults: {passed}/{len(events)} tests passed")

    if passed != len(events):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
