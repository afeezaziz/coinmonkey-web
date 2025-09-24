from __future__ import annotations

"""
Lightweight orchestrator abstraction for agents.

MVP: In-memory stateful orchestrator that simulates start/stop/status without
actually running containers. This allows the web UI to work end-to-end.

Future: Add Docker and Kubernetes backends behind the same interface.
"""

import os
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class AgentState:
    status: str = "stopped"  # running | stopped | error
    container_id: Optional[str] = None
    host_port: Optional[int] = None


class InMemoryOrchestrator:
    def __init__(self) -> None:
        self._state: Dict[str, AgentState] = {}

    def start(self, agent_id: str, env: Optional[Dict[str, str]] | None = None) -> None:
        st = self._state.get(agent_id, AgentState())
        st.status = "running"
        self._state[agent_id] = st

    def stop(self, agent_id: str) -> None:
        st = self._state.get(agent_id, AgentState())
        st.status = "stopped"
        self._state[agent_id] = st

    def status(self, agent_id: str) -> str:
        return self._state.get(agent_id, AgentState()).status

    def delete(self, agent_id: str) -> None:
        self._state.pop(agent_id, None)

    def host_port(self, agent_id: str) -> Optional[int]:
        return None


class DockerOrchestrator:
    """Very small Docker backend. Requires local Docker daemon.

    Note: This is a minimal placeholder; it does not mount configs or secrets yet.
    It simply runs a container per agent with an AGENT_ID env var.
    """

    def __init__(self) -> None:
        try:
            import docker  # type: ignore
        except Exception as e:  # pragma: no cover
            raise RuntimeError("Docker SDK not available: pip install docker") from e
        self._docker = docker.from_env()
        self._image = os.getenv("AGENT_IMAGE", "ghcr.io/coinmonkey/agent-runner:latest")
        self._state: Dict[str, AgentState] = {}
        self._volume_prefix = os.getenv("AGENT_VOLUME_PREFIX", "agent-")

    def _get_container(self, agent_id: str):
        """Retrieve a container by state container_id or by name fallback."""
        st = self._state.get(agent_id)
        try:
            if st and st.container_id:
                return self._docker.containers.get(st.container_id)
        except Exception:
            pass
        # Fallback by name (survives Flask restarts)
        try:
            name = f"agent-{agent_id}"
            return self._docker.containers.get(name)
        except Exception:
            return None

    def start(self, agent_id: str, env: Optional[Dict[str, str]] | None = None) -> None:
        st = self._state.get(agent_id, AgentState())
        # If a container already exists but stopped, try to start; else run new
        c = self._get_container(agent_id)
        if c is not None:
            try:
                c.start()
            except Exception:
                pass
            st.status = "running"
            try:
                c.reload()
                st.container_id = c.id
                ports = c.attrs.get("NetworkSettings", {}).get("Ports", {})
                host = ports.get("8000/tcp")
                if host and isinstance(host, list) and host:
                    st.host_port = int(host[0].get("HostPort"))
            except Exception:
                st.host_port = None
            self._state[agent_id] = st
            return

        env_base = {"AGENT_ID": agent_id}
        if env:
            env_base.update(env)

        # Optional persistent volume for keystore/data
        volumes = None
        keystore_path = env_base.get("KEYSTORE_PATH", "/data")
        volume_name = f"{self._volume_prefix}{agent_id}-data"
        try:
            # Ensure volume exists
            self._docker.volumes.get(volume_name)
        except Exception:
            try:
                self._docker.volumes.create(name=volume_name)
            except Exception:
                volume_name = None
        if volume_name:
            volumes = {volume_name: {"bind": keystore_path, "mode": "rw"}}

        container = self._docker.containers.run(
            self._image,
            name=f"agent-{agent_id}",
            environment=env_base,
            volumes=volumes,
            ports={"8000/tcp": None},  # random host port assignment
            detach=True,
            auto_remove=False,
            restart_policy={"Name": "unless-stopped"},
        )
        st.container_id = container.id
        # determine published host port
        try:
            container.reload()
            ports = container.attrs.get("NetworkSettings", {}).get("Ports", {})
            host = ports.get("8000/tcp")
            if host and isinstance(host, list) and host:
                st.host_port = int(host[0].get("HostPort"))
        except Exception:
            st.host_port = None
        st.status = "running"
        self._state[agent_id] = st

    def stop(self, agent_id: str) -> None:
        st = self._state.get(agent_id)
        if not st or not st.container_id:
            return
        try:
            c = self._docker.containers.get(st.container_id)
            c.stop()
            st.status = "stopped"
            self._state[agent_id] = st
        except Exception:
            st.status = "error"
            self._state[agent_id] = st

    def status(self, agent_id: str) -> str:
        st = self._state.get(agent_id, AgentState())
        c = self._get_container(agent_id)
        if not c:
            # no container found
            return st.status
        try:
            c.reload()
            st.container_id = c.id
            # update host_port if possible
            try:
                ports = c.attrs.get("NetworkSettings", {}).get("Ports", {})
                host = ports.get("8000/tcp")
                if host and isinstance(host, list) and host:
                    st.host_port = int(host[0].get("HostPort"))
            except Exception:
                pass
            status = "running" if c.status == "running" else c.status
            st.status = status
            self._state[agent_id] = st
            return status
        except Exception:
            return "error"

    def host_port(self, agent_id: str) -> Optional[int]:
        st = self._state.get(agent_id, AgentState())
        if st.host_port:
            return st.host_port
        # Try to refresh from container (by id or name)
        c = self._get_container(agent_id)
        if not c:
            return None
        try:
            c.reload()
            st.container_id = c.id
            ports = c.attrs.get("NetworkSettings", {}).get("Ports", {})
            host = ports.get("8000/tcp")
            if host and isinstance(host, list) and host:
                st.host_port = int(host[0].get("HostPort"))
                self._state[agent_id] = st
                return st.host_port
        except Exception:
            return None
        return None

    def delete(self, agent_id: str) -> None:
        st = self._state.pop(agent_id, None)
        if not st or not st.container_id:
            return
        try:
            c = self._docker.containers.get(st.container_id)
            c.remove(force=True)
        except Exception:
            pass
        # Optionally clean up volume (keep by default). Uncomment to prune per delete.
        # try:
        #     vol = self._docker.volumes.get(f"{self._volume_prefix}{agent_id}-data")
        #     vol.remove(force=True)
        # except Exception:
        #     pass


def _select_orchestrator():
    backend = os.getenv("ORCHESTRATOR", "memory").lower()
    if backend == "docker":
        try:
            return DockerOrchestrator()
        except Exception:
            # Fallback to memory if Docker not available
            return InMemoryOrchestrator()
    return InMemoryOrchestrator()


# Singleton instance for app import
orchestrator = _select_orchestrator()
