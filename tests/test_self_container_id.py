import re
from pathlib import Path

ENTRYPOINT = Path(__file__).parent.parent / "entrypoint.sh"


def _load_get_self_container_id(fake_files):
    """Extract get_self_container_id() from entrypoint.sh's embedded
    write_hosts_from_docker heredoc and exec it with a fake `open`, so it
    can be unit tested without a real container / Docker socket."""
    source = ENTRYPOINT.read_text()
    match = re.search(r"def get_self_container_id\(\).*?(?=\ndef )", source, re.DOTALL)
    assert match, "get_self_container_id() not found in entrypoint.sh"

    def fake_open(path, *args, **kwargs):
        import io

        if path not in fake_files:
            raise FileNotFoundError(path)
        return io.StringIO(fake_files[path])

    namespace = {"re": re, "open": fake_open}
    exec(match.group(0), namespace)
    return namespace["get_self_container_id"]


def test_uses_mountinfo_even_when_hostname_is_overridden():
    """Regression test: when this container shares the network namespace of
    another one whose `hostname` was overridden (Compose network_mode:
    service:X), /etc/hostname no longer contains our own container id and
    must not be used directly."""
    real_id = "eb292bc533198f6ab29d301abef3e95cb651068cebdb3e6aea6dc8d84e23cad7"
    mountinfo = (
        "607 590 253:1 /var/lib/docker/containers/{id}/resolv.conf "
        "/etc/resolv.conf rw,relatime - ext4 /dev/vda1 rw\n"
        "608 590 253:1 /var/lib/docker/containers/{id}/hostname "
        "/etc/hostname rw,relatime - ext4 /dev/vda1 rw\n"
        "609 590 253:1 /var/lib/docker/containers/{id}/hosts "
        "/etc/hosts rw,relatime - ext4 /dev/vda1 rw\n"
    ).format(id=real_id)

    get_self_container_id = _load_get_self_container_id(
        {
            "/proc/self/mountinfo": mountinfo,
            "/etc/hostname": "totally-custom.example.com\n",
        }
    )

    assert get_self_container_id() == real_id


def test_falls_back_to_etc_hostname_without_bind_mount():
    """When /etc/hostname isn't bind-mounted the way Docker normally does
    (mountinfo has no matching entry), fall back to the previous
    behaviour of reading /etc/hostname directly."""
    get_self_container_id = _load_get_self_container_id(
        {
            "/proc/self/mountinfo": "",
            "/etc/hostname": "09421ed373a6\n",
        }
    )

    assert get_self_container_id() == "09421ed373a6"
