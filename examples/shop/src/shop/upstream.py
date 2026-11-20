import json
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel

from shop.workload import FROZEN, Workload

REDIS: Final = "redis"
POSTGRES: Final = "postgres"
UPSTREAM_SERVICES: Final = frozenset({REDIS, POSTGRES})
"""The services of the upstream components in point ids."""
PACKET_POINTS: Final = tuple(f"{service}:packet:egress:*:*" for service in sorted(UPSTREAM_SERVICES))
"""The packets each upstream component sends, which the kernel agent can delay; it observes only what it injects, so
these points are configured rather than found in a control."""
REDIS_IMAGE: Final = "redis:7"
POSTGRES_IMAGE: Final = "postgres:16"
AGENT_IMAGE: Final = "python:3.12-alpine"
POSTGRES_PASSWORD: Final = "shop"
REDIS_PORT: Final = 6379
POSTGRES_PORT: Final = 5432
HOST_FROM_NAMESPACE: Final = "10.0.2.2"
"""The host's loopback as a repetition's network namespace reaches it through slirp4netns."""
CONTAINER_CGROUPS: Final = Path("/sys/fs/cgroup/system.slice")
AGENT_SYSCALLS: Final = ("read", "write", "sendto", "recvfrom", "fsync", "fdatasync", "pwrite64")
AGENT_REPORT: Final = "/agent.jsonl"
AGENT_OBSERVATIONS: Final = "agent.jsonl"
AGENT_CONFIG: Final = "agent.config.json"
AGENT_LOG: Final = "agent.log"
UPSTREAM_FILE: Final = "upstream.json"
READY_DEADLINE_S: Final = 60
STOP_GRACE_S: Final = 20


class Container(BaseModel):
    """An upstream component of one repetition: its service name in point ids and its published port."""

    model_config = FROZEN

    service: str
    name: str
    identifier: str
    port: int

    @property
    def cgroup(self) -> str:
        return str(CONTAINER_CGROUPS / f"docker-{self.identifier}.scope")


class Upstream(BaseModel):
    """The infrastructure a repetition's services use, each in a container of its own with fresh state."""

    model_config = FROZEN

    redis: Container
    postgres: Container

    def environment(self) -> dict[str, str]:
        return {"REDIS_URL": f"redis://{HOST_FROM_NAMESPACE}:{self.redis.port}/0",
                "INVENTORY_DATABASE": f"host={HOST_FROM_NAMESPACE} port={self.postgres.port} user=postgres "
                                      f"password={POSTGRES_PASSWORD} dbname=postgres sslmode=disable"}


def docker(*arguments: str, stdin: str | None = None) -> str:
    return subprocess.run(["docker", *arguments], check=True, capture_output=True, text=True,
                          input=stdin).stdout.strip()


def start_container(service: str, name: str, image: str, port: int, *options: str) -> Container:
    identifier = docker("run", "-d", "--name", name, "-p", f"127.0.0.1::{port}", *options, image)
    published = docker("port", name, f"{port}/tcp").splitlines()[0].rpartition(":")[2]
    return Container(service=service, name=name, identifier=identifier, port=int(published))


def wait_until_ready(container: Container, *command: str) -> None:
    started = time.monotonic()
    while subprocess.run(["docker", "exec", container.name, *command], capture_output=True).returncode != 0:
        if time.monotonic() - started > READY_DEADLINE_S:
            raise TimeoutError(f"{container.name} did not answer {' '.join(command)}")
        time.sleep(0.2)


def start_upstream(prefix: str, workload: Workload) -> Upstream:
    """Redis for orders' price cache and PostgreSQL with inventory's stock, seeded from the workload."""
    upstream = Upstream(
        redis=start_container(REDIS, f"{prefix}-{REDIS}", REDIS_IMAGE, REDIS_PORT),
        postgres=start_container(POSTGRES, f"{prefix}-{POSTGRES}", POSTGRES_IMAGE, POSTGRES_PORT,
                                 "-e", f"POSTGRES_PASSWORD={POSTGRES_PASSWORD}", "--tmpfs", "/var/lib/postgresql/data"))
    wait_until_ready(upstream.redis, "redis-cli", "ping")
    wait_until_ready(upstream.postgres, "pg_isready", "-h", "127.0.0.1", "-U", "postgres")
    stock = ", ".join(f"('{sku}', {workload.stock_per_sku})"
                      for tenant in workload.tenant_names() for sku in workload.skus(tenant))
    docker("exec", "-i", upstream.postgres.name, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1",
           stdin=f"CREATE TABLE stock (sku TEXT PRIMARY KEY, available INTEGER); INSERT INTO stock VALUES {stock};")
    return upstream


def remove_containers(prefix: str) -> None:
    """Remove a repetition's containers, stopping them first so that a running agent detaches what it attached."""
    names = docker("ps", "-aq", "--filter", f"name=^{prefix}-").split()
    if names:
        docker("stop", "-t", str(STOP_GRACE_S), *names)
        docker("rm", *names)


def host_peer(container: Container) -> str:
    """The host-side end of the container's virtual cable, the device whose index its eth0 links to."""
    return socket.if_indextoname(int(docker("exec", container.name, "cat", "/sys/class/net/eth0/iflink")))


def agent_config(upstream: Upstream, flush_seconds: float) -> dict[str, Any]:
    """The kernel agent's services: each container's cgroup, its own interface, which transmits its egress, and the
    host side of its cable, which transmits its ingress."""
    return {"options": {"jsonl": {"flush_seconds": flush_seconds}, "ebpf": {"syscalls": list(AGENT_SYSCALLS), "services": {
        container.service: {"cgroups": [container.cgroup], "devices": [
            {"netns": docker("inspect", "-f", "{{.NetworkSettings.SandboxKey}}", container.name), "name": "eth0",
             "transmits": "egress"},
            {"name": host_peer(container), "transmits": "ingress"}]}
        for container in (upstream.redis, upstream.postgres)}}}}


def start_agent(directory: Path, rules: Path, upstream: Upstream, sdk: Path, prefix: str, flush_seconds: float) -> str:
    """The eBPF agent for the upstream containers, privileged in a container of its own, reading the repetition's
    rules; its observations stay inside the container until it stops, so that root never owns a file of ours."""
    (directory / AGENT_CONFIG).write_text(json.dumps(agent_config(upstream, flush_seconds)))
    name = f"{prefix}-agent"
    docker("run", "-d", "--name", name, "--privileged", "--network=host", "--cgroupns=host",
           "-v", "/sys/kernel/tracing:/sys/kernel/tracing", "-v", "/var/run/docker/netns:/var/run/docker/netns",
           "-v", f"{sdk / 'ebpf' / 'fpebpf'}:/fpebpf:ro", "-v", f"{directory / AGENT_CONFIG}:/work/config.json:ro",
           "-v", f"{rules}:/work/rules.json:ro", "-e", "FAULTPOINT_CONFIG=/work/config.json",
           "-e", "FAULTPOINT_RULES=/work/rules.json", "-e", f"FAULTPOINT_REPORT={AGENT_REPORT}", AGENT_IMAGE, "/fpebpf")
    return name


def stop_agent(name: str, directory: Path) -> None:
    """Stop the agent, which detaches what it attached and writes its last counts, and keep its observations."""
    docker("stop", "-t", str(STOP_GRACE_S), name)
    with (directory / AGENT_LOG).open("w") as log:
        subprocess.run(["docker", "logs", name], check=True, stdout=log, stderr=subprocess.STDOUT)
    code = docker("inspect", "-f", "{{.State.ExitCode}}", name)
    if code != "0":
        raise RuntimeError(f"the kernel agent {name} ended with {code}, see {directory / AGENT_LOG}")
    docker("cp", f"{name}:{AGENT_REPORT}", str(directory / AGENT_OBSERVATIONS))
