import re
from pathlib import Path

ENTRYPOINT = Path(__file__).parent.parent / "entrypoint.sh"


def test_docker_get_calls_do_not_pin_an_api_version():
    """Regression test: a hardcoded API version prefix (e.g. /v1.41/) breaks
    as soon as the Docker Engine raises its minimum supported API version
    past it, which newer engines reject with 400 Bad Request. docker_get()
    calls must use unversioned paths so the daemon picks its own latest
    supported version."""
    source = ENTRYPOINT.read_text()
    calls = re.findall(r'docker_get\(\s*f?"([^"]*)"', source)
    assert calls, "no docker_get(...) calls found in entrypoint.sh"

    pinned = [path for path in calls if re.match(r"/v\d+\.\d+/", path)]
    assert not pinned, f"docker_get() calls pin an API version: {pinned}"
