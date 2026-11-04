"""PolicyOps application package.

Dependency direction: api -> services -> domain; worker -> orchestration ->
services; adapters -> ports/domain. The domain imports no framework code.
"""

__version__ = "0.1.0"
