import logging
import time

import pytest
from plumbum.cmd import docker

logger = logging.getLogger()


@pytest.mark.timeout(30)
def test_container_starts_and_healthcheck_ok(container_factory):
    with container_factory(target="example.com") as c:
        deadline = time.time() + 20
        last_err = None
        while time.time() < deadline:
            try:
                docker("exec", c, "healthcheck")
                return
            except Exception as e:
                last_err = e
                time.sleep(0.5)
        raise last_err
