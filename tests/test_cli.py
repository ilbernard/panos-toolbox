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
