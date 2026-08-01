from pathlib import Path


def test_generated_audit_output_is_ignored_and_documented():
    repository_root = Path(__file__).parents[2]
    ignore_entries = (repository_root / ".gitignore").read_text(encoding="utf-8").splitlines()
    readme = (repository_root / "README.md").read_text(encoding="utf-8")

    assert "/audit.jsonl" in ignore_entries
    assert "generated local output" in readme
