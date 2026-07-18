from __future__ import annotations

from pathlib import Path

import pytest

from app.settings import Settings, SettingsError


def test_project_env_key_wins_without_ambient_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-key-must-not-be-used")
    env_path = tmp_path / ".env"
    env_path.write_text("OPENAI_API_KEY=project-key-only\n", encoding="utf-8")

    settings = Settings.load(env_path)

    assert settings.openai_api_key == "project-key-only"
    assert settings.reasoner_mode == "openai"


def test_explicit_openai_mode_refuses_ambient_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-key-must-not-be-used")
    env_path = tmp_path / ".env"
    env_path.write_text("REASONER_MODE=openai\n", encoding="utf-8")

    with pytest.raises(SettingsError, match="project file"):
        Settings.load(env_path)


def test_project_key_does_not_interpolate_from_ambient_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOME_OTHER_KEY", "ambient-key-must-not-be-used")
    env_path = tmp_path / ".env"
    env_path.write_text(
        "REASONER_MODE=openai\nOPENAI_API_KEY=${SOME_OTHER_KEY}\n", encoding="utf-8"
    )

    with pytest.raises(SettingsError, match="interpolation is disabled"):
        Settings.load(env_path)


def test_missing_project_key_defaults_to_mock(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("", encoding="utf-8")

    settings = Settings.load(env_path)

    assert settings.reasoner_mode == "mock"
    assert settings.openai_api_key is None


def test_non_budget_model_requires_explicit_opt_in(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text(
        "OPENAI_API_KEY=project-key-only\nOPENAI_MODEL=gpt-4.1\n",
        encoding="utf-8",
    )

    with pytest.raises(SettingsError, match="ALLOW_NON_BUDGET_MODEL"):
        Settings.load(env_path)
