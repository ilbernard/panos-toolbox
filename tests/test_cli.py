from panos_toolbox.cli import main


def test_version(capsys):
    assert main(["--version"]) == 0
    assert "panos-toolbox" in capsys.readouterr().out


def test_unknown_tool_returns_error():
    assert main(["nope", "nothing"]) == 2


def test_console_help_is_wired_without_gui_dependencies(capsys):
    try:
        main(["firewall", "console", "-h"])
    except SystemExit as exc:
        assert exc.code == 0
    assert "usage: panos-toolbox firewall console" in capsys.readouterr().out


def test_tsf_analyzer_help_is_wired(capsys):
    try:
        main(["tsf", "analyze", "-h"])
    except SystemExit as exc:
        assert exc.code == 0
    assert "usage" in capsys.readouterr().out


def test_runtime_tools_are_registered(capsys):
    for tool in ("capture", "report"):
        try:
            main(["runtime", tool, "-h"])
        except SystemExit as exc:
            assert exc.code == 0
        assert f"usage: panos-toolbox runtime {tool}" in capsys.readouterr().out


def test_runtime_capture_rejects_a_password_argument(capsys):
    try:
        main(["runtime", "capture", "--host", "h", "--user", "u", "--password", "x"])
    except SystemExit as exc:
        assert exc.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err
