from panos_toolbox.cli import main


def test_version(capsys):
    assert main(["--version"]) == 0
    assert "panos-toolbox" in capsys.readouterr().out


def test_unknown_tool_returns_error():
    assert main(["nope", "nothing"]) == 2


def test_tsf_analyzer_help_is_wired(capsys):
    try:
        main(["tsf", "analyze", "-h"])
    except SystemExit as exc:
        assert exc.code == 0
    assert "usage" in capsys.readouterr().out
