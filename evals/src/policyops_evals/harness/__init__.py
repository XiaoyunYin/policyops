"""Pure compatibility helpers between the pinned upstream harness and the shared conversation contracts (T29).

This package never imports the application. It holds only pure mappings: upstream tool descriptors to strict
`ToolDescriptor`/`ToolCatalog` (with the reverse argument mapping), and upstream visible messages to and from the
conversation DTOs. The registered agent factory, the process bridge, simulator and judge routing and the trial
driver are later slices.
"""
