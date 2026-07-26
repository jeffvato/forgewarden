from swarm.adapters import _safe_agent_environment


def test_generic_agent_environment_excludes_common_service_credentials(monkeypatch):
    sensitive = {
        "GEMINI_API_KEY": "gemini-secret",
        "GOOGLE_API_KEY": "google-secret",
        "ANTHROPIC_API_KEY": "anthropic-secret",
        "HF_TOKEN": "hf-secret",
        "GITHUB_TOKEN": "github-secret",
        "SLACK_BOT_TOKEN": "slack-secret",
        "TELEGRAM_BOT_TOKEN": "telegram-secret",
        "OAUTH_CLIENT_ID": "oauth-id",
        "OAUTH_CLIENT_SECRET": "oauth-secret",
        "AWS_ACCESS_KEY_ID": "aws-id",
        "CUSTOM_SECRET_VALUE": "custom-secret",
    }
    for key, value in sensitive.items():
        monkeypatch.setenv(key, value)

    filtered = _safe_agent_environment({"SWARM_ROLE": "GEMINI_READ_ONLY"})

    assert all(key not in filtered for key in sensitive)
    assert filtered["SWARM_ROLE"] == "GEMINI_READ_ONLY"
    assert filtered["SWARM_NETWORK_BLOCKED"] == "1"
    assert filtered.get("HTTP_PROXY") is None
    assert filtered.get("HTTPS_PROXY") is None
    assert filtered.get("ALL_PROXY") is None
