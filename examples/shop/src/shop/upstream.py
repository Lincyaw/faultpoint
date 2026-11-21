import json
import shlex
import shutil
import socket
import subprocess
import time
from hashlib import sha256
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel, JsonValue

from shop.workload import FROZEN

REDIS: Final = "redis"
POSTGRES: Final = "postgres"
REDIS_IMAGE: Final = "redis:7"
POSTGRES_IMAGE: Final = "postgres:16"
UNSCOPED_TARGETS: Final = {service: f"the {service} container ({image})"
                           for service, image in ((REDIS, REDIS_IMAGE), (POSTGRES, POSTGRES_IMAGE))}
"""What a fault no rule can scope acts on, by the service of its point: the whole of a container."""
UPSTREAM_SERVICES: Final = frozenset(UNSCOPED_TARGETS)
"""The services of the upstream components in point ids."""
PACKET_POINTS: Final = tuple(f"{service}:packet:egress:*:*" for service in sorted(UPSTREAM_SERVICES))
"""The packets each upstream component sends, which the kernel agent can delay; it observes only what it injects, so
these points are configured rather than found in a control."""
SERVER_COMMANDS: Final = {REDIS: "redis-server", POSTGRES: "postgres"}
"""What each image's entrypoint runs by default."""
NATIVE_FUNCTIONS: Final[dict[str, tuple[dict[str, Any], ...]]] = {
    REDIS: ({"file": "/usr/local/bin/redis-server", "symbol": "lookupKey", "kind": "call",
             "result": {"registers": ["ax"], "outcome": "ax", "type": "pointer", "error": "zero"},
             "errors": {"NULL": [{"constant": 0}]},
             # Only lookups for reading may find nothing: a write lookup that does trips Redis' own assertion.
             "predicate": {"register": "dx", "mask": 8, "equals": 0},
             "clones": {"lookupKey.constprop.0": None, "lookupKey.constprop.1": {}}},),
    POSTGRES: ({"file": "/usr/lib/postgresql/16/bin/postgres", "symbol": "pq_getbyte", "kind": "call",
                "result": {"registers": ["ax"], "outcome": "ax", "type": "int32", "error": "negative"},
                "errors": {"EOF": [{"constant": -1}]}},),
}
"""The functions of each upstream component where the kernel agent places points, in its configuration's terms: a
read of Redis that finds no key, and a backend of PostgreSQL reading the end of its client's connection, which every
caller of pq_getbyte handles as the client leaving."""
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
AGENT_CATALOG: Final = "/catalog"
"""Where the kernel agent's container holds a scan's hook catalog: the scan writes it there, the agent reads it."""
TRACING_MOUNTS: Final = ("-v", "/sys/kernel/tracing:/sys/kernel/tracing")
DEBUG_MOUNTS: Final = ("-v", "/sys/kernel/debug:/sys/kernel/debug")
"""The scan reads the kernel's functions under debugfs."""
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


class AgentObservation(BaseModel):
    """What the kernel agent observes besides the points it injects at: the syscalls whose natural results it reports,
    every syscall when none are listed, and per upstream service the records of the build's hook catalog it attaches,
    in the shape of the agent's hooks options."""

    model_config = FROZEN

    syscalls: tuple[str, ...] | None = AGENT_SYSCALLS
    hooks: dict[str, dict[str, JsonValue]] = {}


class Upstream(BaseModel):
    """The infrastructure a repetition's services use, each in a container of its own with fresh state."""

    model_config = FROZEN

    redis: Container
    postgres: Container

    @property
    def redis_url(self) -> str:
        return f"redis://{HOST_FROM_NAMESPACE}:{self.redis.port}/0"

    @property
    def database(self) -> str:
        """The connection string of the PostgreSQL database as libpq and pgx read it."""
        return (f"host={HOST_FROM_NAMESPACE} port={self.postgres.port} user=postgres password={POSTGRES_PASSWORD} "
                "dbname=postgres sslmode=disable")


def docker(*arguments: str, stdin: str | None = None) -> str:
    return subprocess.run(["docker", *arguments], check=True, capture_output=True, text=True,
                          input=stdin).stdout.strip()


def private_files_command(service: str) -> str:
    """The image's default command, run after copying every file the kernel agent probes into the container's own
    writable layer, since a probe on a file of a shared image layer traps every container that maps it."""
    files = sorted({function["file"] for function in NATIVE_FUNCTIONS[service]})
    copies = [f"cp {shlex.quote(file)} {shlex.quote(file)}.copy && mv {shlex.quote(file)}.copy {shlex.quote(file)}"
              for file in files]
    return " && ".join([*copies, f"exec docker-entrypoint.sh {SERVER_COMMANDS[service]}"])


def start_container(service: str, name: str, image: str, port: int, *options: str) -> Container:
    identifier = docker("run", "-d", "--name", name, "-p", f"127.0.0.1::{port}", *options, "--entrypoint", "sh",
                        image, "-c", private_files_command(service))
    published = docker("port", name, f"{port}/tcp").splitlines()[0].rpartition(":")[2]
    return Container(service=service, name=name, identifier=identifier, port=int(published))


def wait_until_ready(container: Container, *command: str) -> None:
    started = time.monotonic()
    while subprocess.run(["docker", "exec", container.name, *command], capture_output=True).returncode != 0:
        if time.monotonic() - started > READY_DEADLINE_S:
            raise TimeoutError(f"{container.name} did not answer {' '.join(command)}")
        time.sleep(0.2)


def start_upstream(prefix: str, sql: str, redis_commands: list[str]) -> Upstream:
    """A fresh Redis and PostgreSQL, the database seeded by running sql and the cache by the Redis commands."""
    upstream = Upstream(
        redis=start_container(REDIS, f"{prefix}-{REDIS}", REDIS_IMAGE, REDIS_PORT),
        postgres=start_container(POSTGRES, f"{prefix}-{POSTGRES}", POSTGRES_IMAGE, POSTGRES_PORT,
                                 "-e", f"POSTGRES_PASSWORD={POSTGRES_PASSWORD}", "--tmpfs", "/var/lib/postgresql/data"))
    wait_until_ready(upstream.redis, "redis-cli", "ping")
    wait_until_ready(upstream.postgres, "pg_isready", "-h", "127.0.0.1", "-U", "postgres")
    docker("exec", "-i", upstream.postgres.name, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", stdin=sql)
    docker("exec", "-i", upstream.redis.name, "redis-cli", stdin="\n".join(redis_commands))
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


def agent_config(upstream: Upstream, flush_seconds: float, observation: AgentObservation) -> dict[str, Any]:
    """The kernel agent's services: each container's cgroup, its own interface, which transmits its egress, and the
    host side of its cable, which transmits its ingress; the functions of each container it places points in; and
    what it observes besides."""
    containers = (upstream.redis, upstream.postgres)
    return {"options": {"jsonl": {"flush_seconds": flush_seconds}, "ebpf": {
        "services": {container.service: {"cgroups": [container.cgroup], "devices": [
            {"netns": docker("inspect", "-f", "{{.NetworkSettings.SandboxKey}}", container.name), "name": "eth0",
             "transmits": "egress"},
            {"name": host_peer(container), "transmits": "ingress"}]} for container in containers},
        "functions": [{"service": container.service, **function}
                      for container in containers for function in NATIVE_FUNCTIONS[container.service]],
        **({"syscalls": list(observation.syscalls)} if observation.syscalls is not None else {}),
        **({"hooks": observation.hooks, "catalog": AGENT_CATALOG} if observation.hooks else {})}}}


def start_agent(directory: Path, rules: Path, upstream: Upstream, sdk: Path, prefix: str, flush_seconds: float,
                observation: AgentObservation, catalog: Path) -> str:
    """The eBPF agent for the upstream containers, privileged in a container of its own, reading the repetition's
    rules and, when it attaches hooks, the build's hook catalog; its observations stay inside the container until it
    stops, so that root never owns a file of ours. It sees the host's processes, to open a container's files through
    the root of a process in the container's cgroup."""
    (directory / AGENT_CONFIG).write_text(json.dumps(agent_config(upstream, flush_seconds, observation)))
    name = f"{prefix}-agent"
    catalog_mounts = ("-v", f"{catalog}:{AGENT_CATALOG}:ro") if observation.hooks else ()
    docker("run", "-d", "--name", name, "--privileged", "--network=host", "--cgroupns=host", "--pid=host",
           *TRACING_MOUNTS, "-v", "/var/run/docker/netns:/var/run/docker/netns", *catalog_mounts,
           "-v", f"{sdk / 'ebpf' / 'fpebpf'}:/fpebpf:ro", "-v", f"{directory / AGENT_CONFIG}:/work/config.json:ro",
           "-v", f"{rules}:/work/rules.json:ro", "-e", "FAULTPOINT_CONFIG=/work/config.json",
           "-e", "FAULTPOINT_RULES=/work/rules.json", "-e", f"FAULTPOINT_REPORT={AGENT_REPORT}", AGENT_IMAGE, "/fpebpf")
    return name


def scan_hooks(sdk: Path, catalog: Path) -> None:
    """Write the kernel agent's hook catalog of the upstream images, once per build: every function, USDT probe and
    kernel record of the files a fresh container of each image maps, with the build id of each file, which the agent
    checks when it attaches a record in a later container."""
    prefix = f"fp-scan-{sha256(str(catalog).encode()).hexdigest()[:12]}"
    remove_containers(prefix)
    try:
        upstream = start_upstream(prefix, "", [])
        config = catalog.with_name(f"{catalog.name}.scan.json")
        services = {container.service: {"cgroups": [container.cgroup]}
                    for container in (upstream.redis, upstream.postgres)}
        config.write_text(json.dumps({"options": {"ebpf": {"services": services}}}))
        name = f"{prefix}-scanner"
        docker("run", "--name", name, "--privileged", "--pid=host", "--cgroupns=host", *TRACING_MOUNTS, *DEBUG_MOUNTS,
               "-v", f"{sdk / 'ebpf' / 'fpebpf'}:/fpebpf:ro", "-v", f"{config}:/work/config.json:ro",
               "-e", "FAULTPOINT_CONFIG=/work/config.json", AGENT_IMAGE, "/fpebpf", "scan", AGENT_CATALOG)
        shutil.rmtree(catalog, ignore_errors=True)
        docker("cp", f"{name}:{AGENT_CATALOG}", str(catalog))
    finally:
        remove_containers(prefix)


def stop_agent(name: str, directory: Path) -> None:
    """Stop the agent, which detaches what it attached and writes its last counts, and keep its observations."""
    docker("stop", "-t", str(STOP_GRACE_S), name)
    with (directory / AGENT_LOG).open("w") as log:
        subprocess.run(["docker", "logs", name], check=True, stdout=log, stderr=subprocess.STDOUT)
    code = docker("inspect", "-f", "{{.State.ExitCode}}", name)
    if code != "0":
        raise RuntimeError(f"the kernel agent {name} ended with {code}, see {directory / AGENT_LOG}")
    docker("cp", f"{name}:{AGENT_REPORT}", str(directory / AGENT_OBSERVATIONS))
