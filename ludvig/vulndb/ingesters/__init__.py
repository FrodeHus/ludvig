from ._github_advisories import (
    read_advisory as github_read_advisory,
    read_repository as github_read_repository,
)

__all__ = ["github_read_advisory", "github_read_repository"]
