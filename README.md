# Bosun

Single-server node agent and panel. Runs standalone with its own local UI, or is adopted by a [Captain](../captain) panel, at which point local settings are superseded by the panel.

Drives upstream proxy cores (sing-box, Xray, mita) as child processes; no forked cores.
