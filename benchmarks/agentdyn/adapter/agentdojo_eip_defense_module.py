"""AgentDyn --module-to-load compatibility entry point."""
from eip_execution.adapters.agentdyn import defense_module as _impl
from eip_execution.adapters.agentdyn.defense_module import *  # noqa: F401,F403

_TerminalGuardedExecutor = _impl._TerminalGuardedExecutor
_SchemaHidingLLM = _impl._SchemaHidingLLM
_ReadResultIsolationLLM = _impl._ReadResultIsolationLLM
_is_terminal_assistant = _impl._is_terminal_assistant

# Only the explicitly requested compatibility entry point installs the legacy hook.
_impl.install_legacy_hook()
