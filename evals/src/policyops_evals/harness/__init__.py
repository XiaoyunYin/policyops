"""Pure compatibility helpers between the pinned upstream harness and the shared conversation contracts (T29).

This package never imports the application, and this `__init__` imports nothing. `tools` and `messages` hold pure
mappings: upstream tool descriptors to strict `ToolDescriptor`/`ToolCatalog` (with the reverse argument mapping), and
upstream visible messages to and from the conversation DTOs. `adapter` (the registered upstream agent factory over an
injected bridge) imports upstream on load: import it only in an interpreter whose upstream import side effects are
disabled. The process bridge, simulator and judge routing and the trial driver are later slices.
"""
