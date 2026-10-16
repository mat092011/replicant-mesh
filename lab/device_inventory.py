"""Local hardware inventory and explicit, bounded model-fit planning.

This module never downloads models or infers model memory from the prototype
checkpoint. The planner only adds caller-supplied component budgets.
"""

import argparse
import ctypes
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys


PLACEMENTS = ("coordinator", "worker-1", "worker-2", "worker-3")
COORDINATOR_OWNERSHIP = {"input_embeddings", "final_norm", "output_head"}
DEFAULT_LAYER_RANGES = {"worker-1": [0, 3], "worker-2": [3, 6], "worker-3": [6, 8]}


def _run(command, timeout=3):
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _windows_memory():
    script = "(Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | ConvertTo-Json -Compress)"
    raw = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script])
    if raw:
        try:
            values = json.loads(raw)
            return {"total_bytes": int(values["TotalVisibleMemorySize"]) * 1024,
                    "available_bytes": int(values["FreePhysicalMemory"]) * 1024,
                    "source": "Windows CIM snapshot"}
        except (ValueError, KeyError, TypeError):
            pass
    class MemoryStatus(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
    status = MemoryStatus()
    status.dwLength = ctypes.sizeof(status)
    if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return {"total_bytes": status.ullTotalPhys, "available_bytes": status.ullAvailPhys,
                "source": "Windows GlobalMemoryStatusEx snapshot"}
    return None


def _memory():
    if os.name == "nt":
        return _windows_memory()
    if hasattr(os, "sysconf"):
        try:
            page_size = os.sysconf("SC_PAGE_SIZE")
            total = page_size * os.sysconf("SC_PHYS_PAGES")
            available_pages = os.sysconf("SC_AVPHYS_PAGES")
            return {"total_bytes": total, "available_bytes": page_size * available_pages,
                    "source": "OS sysconf snapshot"}
        except (ValueError, OSError, AttributeError):
            pass
    return None


def _cpu_name():
    if os.name == "nt":
        raw = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                    "(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)"])
        if raw:
            return raw.splitlines()[0].strip()
    if sys.platform.startswith("linux"):
        try:
            for line in Path("/proc/cpuinfo").read_text(errors="replace").splitlines():
                if line.lower().startswith(("model name", "hardware")) and ":" in line:
                    return line.split(":", 1)[1].strip()
        except OSError:
            pass
    if sys.platform == "darwin":
        raw = _run(["sysctl", "-n", "machdep.cpu.brand_string"])
        if raw:
            return raw
    return platform.processor() or "unavailable"


def _gpus():
    executable = shutil.which("nvidia-smi")
    if executable is None:
        return {"status": "unknown", "reason": "nvidia-smi unavailable; GPU vendor and free VRAM not established",
                "devices": []}
    raw = _run([executable, "--query-gpu=name,memory.total,memory.free,driver_version",
                "--format=csv,noheader,nounits"], timeout=5)
    if raw is None:
        return {"status": "unknown", "reason": "NVIDIA query failed; GPU capacity not established",
                "devices": []}
    devices = []
    try:
        for line in raw.splitlines():
            columns = [part.strip() for part in line.split(",")]
            if len(columns) != 4 or not columns[0]:
                raise ValueError("unexpected nvidia-smi row")
            total_mib, free_mib = int(columns[1]), int(columns[2])
            if total_mib < 0 or free_mib < 0 or free_mib > total_mib:
                raise ValueError("invalid VRAM measurement")
            devices.append({"name": columns[0], "memory_total_bytes": total_mib * 1024 * 1024,
                            "memory_free_bytes": free_mib * 1024 * 1024,
                            "driver_version": columns[3]})
    except ValueError:
        return {"status": "unknown", "reason": "NVIDIA query format unrecognized; GPU capacity not established",
                "devices": []}
    return {"status": "available" if devices else "unknown",
            "reason": None if devices else "nvidia-smi found no NVIDIA devices",
            "devices": devices}


def collect_inventory():
    """Collect sanitized local CPU, RAM, and supported NVIDIA GPU observations."""
    return {"schema_version": 1,
            "basis": "host measurement snapshot; free capacity is time-sensitive",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "system": {"os": platform.system(), "os_release": platform.release(),
                       "architecture": platform.machine()},
            "cpu": {"name": _cpu_name(), "logical_count": os.cpu_count()},
            "memory": _memory(), "gpu": _gpus()}


def _bytes(value, label):
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer byte count")
    return value


def plan_fit(configuration):
    """Assess explicit component budgets against explicit per-device capacities.

    This is arithmetic, not a runtime measurement. Component budgets may be
    estimates; the basis is retained so the result cannot imply measured fit.
    """
    if not isinstance(configuration, dict):
        raise ValueError("planner input must be a JSON object")
    for field in ("model", "revision", "precision"):
        if not isinstance(configuration.get(field), str) or not configuration[field].strip():
            raise ValueError(f"{field} must be a nonempty string identifying these budgets")
    total_layers = configuration.get("total_layers", 8)
    ranges = configuration.get("layer_ranges", DEFAULT_LAYER_RANGES)
    if type(total_layers) is not int or total_layers <= 0:
        raise ValueError("total_layers must be a positive integer")
    if not isinstance(ranges, dict) or set(ranges) != set(PLACEMENTS[1:]):
        raise ValueError("layer_ranges must define exactly worker-1, worker-2, and worker-3")
    normalized_ranges = {}
    for worker in PLACEMENTS[1:]:
        interval = ranges[worker]
        if (not isinstance(interval, list) or len(interval) != 2
                or any(type(value) is not int for value in interval)
                or interval[0] < 0 or interval[1] <= interval[0]):
            raise ValueError(f"{worker} layer range must contain increasing integer bounds")
        normalized_ranges[worker] = interval
    cursor = 0
    for worker in PLACEMENTS[1:]:
        interval = normalized_ranges[worker]
        if interval[0] != cursor:
            raise ValueError("layer ranges must be contiguous, nonoverlapping, and start at zero")
        cursor = interval[1]
    if cursor != total_layers:
        raise ValueError("layer ranges must cover every layer exactly once through total_layers")
    devices = configuration.get("devices")
    components = configuration.get("components")
    assignments = configuration.get("assignments")
    if not isinstance(devices, list) or not devices:
        raise ValueError("at least one device capacity is required")
    if not isinstance(components, list) or not components:
        raise ValueError("explicit component budgets are required")
    if not isinstance(assignments, dict) or set(assignments) != set(PLACEMENTS):
        raise ValueError("assignments must map coordinator and all three workers to device indexes")
    capacities = []
    for index, device in enumerate(devices):
        if not isinstance(device, dict) or "usable_bytes" not in device:
            raise ValueError(f"device {index} requires usable_bytes")
        capacities.append(_bytes(device["usable_bytes"], f"device {index} usable_bytes"))
        if device.get("capacity_basis") not in ("measured", "estimated", "configured"):
            raise ValueError(f"device {index} capacity_basis must be measured, estimated, or configured")
        if device.get("memory_kind") not in ("ram", "vram"):
            raise ValueError(f"device {index} memory_kind must be ram or vram; these pools are independent")
    for placement, index in assignments.items():
        if type(index) is not int or not 0 <= index < len(devices):
            raise ValueError(f"assignment for {placement} must be a valid device index")

    seen_names = set()
    ownership = {name: set() for name in PLACEMENTS}
    by_placement = {name: {"weights_bytes": 0, "kv_cache_bytes": 0,
                           "temporary_headroom_bytes": 0, "component_names": []}
                    for name in PLACEMENTS}
    layer_ranges = {}
    budget_bases = set()
    for component in components:
        if not isinstance(component, dict):
            raise ValueError("each component budget must be an object")
        name, placement = component.get("name"), component.get("placement")
        if not isinstance(name, str) or not name or name in seen_names:
            raise ValueError("component names must be unique nonempty strings")
        seen_names.add(name)
        if placement not in PLACEMENTS:
            raise ValueError(f"unknown component placement {placement!r}")
        owners = component.get("owns")
        if not isinstance(owners, list) or not owners or not all(isinstance(x, str) for x in owners):
            raise ValueError(f"component {name} requires explicit owns entries")
        if len(set(owners)) != len(owners) or ownership[placement].intersection(owners):
            raise ValueError(f"component ownership is duplicated at {placement}")
        ownership[placement].update(owners)
        for field, total in (("weight_bytes", "weights_bytes"), ("kv_cache_bytes", "kv_cache_bytes"),
                             ("temporary_headroom_bytes", "temporary_headroom_bytes")):
            if field not in component:
                raise ValueError(f"component {name} must explicitly declare {field}")
            by_placement[placement][total] += _bytes(component[field], f"{name} {field}")
        basis = component.get("budget_basis")
        if basis not in ("measured", "estimated", "configured"):
            raise ValueError(f"component {name} budget_basis must be measured, estimated, or configured")
        budget_bases.add(basis)
        by_placement[placement]["component_names"].append(name)
        if placement != "coordinator":
            expected = normalized_ranges[placement]
            supplied = component.get("layer_range")
            if supplied != expected:
                raise ValueError(f"{placement} must own its fixed contiguous range {expected}")
            if owners != [f"layers[{expected[0]}:{expected[1]}]"]:
                raise ValueError(f"{placement} must explicitly own only layers[{expected[0]}:{expected[1]}]")
            if placement in layer_ranges:
                raise ValueError(f"{placement} layer assignment must be represented by one component")
            layer_ranges[placement] = supplied
    if ownership["coordinator"] != COORDINATOR_OWNERSHIP:
        raise ValueError("coordinator must explicitly account for input_embeddings, final_norm, and output_head exactly once; tied weights may share one component with both embedding/head owners")
    for placement in normalized_ranges:
        if placement not in layer_ranges:
            raise ValueError(f"missing fixed layer assignment for {placement}")

    placement_requirements = {name: sum(values[key] for key in
                                ("weights_bytes", "kv_cache_bytes", "temporary_headroom_bytes"))
                              for name, values in by_placement.items()}
    required_total = sum(placement_requirements.values())
    device_use = [0] * len(devices)
    placement_results = {}
    assignment_fits = True
    for placement, requirement in placement_requirements.items():
        index = assignments[placement]
        device_use[index] += requirement
        fits = requirement <= capacities[index]
        assignment_fits &= fits
        placement_results[placement] = {**by_placement[placement], "required_bytes": requirement,
                                        "assigned_device_index": index,
                                        "capacity_bytes": capacities[index], "fits": fits}
    requirements_by_kind = {kind: 0 for kind in ("ram", "vram")}
    capacities_by_kind = {kind: 0 for kind in ("ram", "vram")}
    for placement, requirement in placement_requirements.items():
        device_index = assignments[placement]
        requirements_by_kind[devices[device_index]["memory_kind"]] += requirement
    for index, device in enumerate(devices):
        capacities_by_kind[device["memory_kind"]] += capacities[index]
    aggregate_fit = all(requirements_by_kind[kind] <= capacities_by_kind[kind]
                        for kind in requirements_by_kind)
    used_kinds = [kind for kind, requirement in requirements_by_kind.items() if requirement]
    if len(used_kinds) == 1:
        single_kind = used_kinds[0]
        single_fit = any(required_total <= capacities[index]
                         for index in range(len(devices))
                         if devices[index]["memory_kind"] == single_kind)
        single_fit_reason = None
    else:
        single_fit = None
        single_fit_reason = "components use both RAM and VRAM; inventory does not map their capacities to one physical device's separate pools"
    whole_budget_single_pool_fit = any(required_total <= capacity for capacity in capacities)
    assignment_fit = assignment_fits and all(device_use[i] <= capacities[i]
                                               for i in range(len(devices)))
    device_results = [{"device_index": i, "usable_bytes": capacity,
                       "assigned_required_bytes": device_use[i],
                       "assigned_fit": device_use[i] <= capacity}
                      for i, capacity in enumerate(capacities)]
    return {"schema_version": 1, "model": configuration.get("model"),
            "precision": configuration.get("precision"),
            "result_basis": "arithmetic over explicit budgets; not execution evidence",
            "memory_pool_note": "RAM and VRAM are independent pools; aggregate capacity is evaluated within each kind. single_device_fit is available only when all assigned components use one memory kind and compares the whole budget against one device of that kind.",
            "device_capacity_basis": [d.get("capacity_basis", "unspecified") for d in devices],
            "device_memory_kinds": [d["memory_kind"] for d in devices],
            "model_revision": configuration["revision"],
            "total_layers": total_layers,
            "layer_ranges": normalized_ranges,
            "component_budget_basis": sorted(budget_bases),
            "required_total_bytes": required_total,
            "single_device_fit": single_fit,
            "single_device_fit_unavailable_reason": single_fit_reason,
            "whole_budget_single_pool_fit": whole_budget_single_pool_fit,
            "aggregate_capacity_fit": aggregate_fit,
            "assigned_stage_fit": assignment_fit,
            "placements": placement_results, "devices": device_results}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Sanitized local inventory and explicit model memory-fit planner",
        epilog="Examples: python -m lab.device_inventory inventory; "
               "python -m lab.device_inventory plan budgets.json")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("inventory", help="snapshot CPU, RAM, and supported NVIDIA GPU data",
        description="Print OS/CPU/RAM observations and NVIDIA name, total/free VRAM, and driver "
                    "when nvidia-smi is available. Unsupported GPU inventory stays unknown; "
                    "hostnames, addresses, and serials are omitted.")
    plan_parser = subparsers.add_parser("plan", help="add explicit component budgets against explicit device capacities",
        description="Read measured or configured per-device usable bytes plus explicit weights, "
                    "KV-cache bytes, and temporary headroom for coordinator and three contiguous "
                    "worker ranges. Reports single-device, aggregate-capacity, "
                    "and assigned-stage arithmetic separately; this does not measure runtime fit.")
    plan_parser.add_argument("configuration", type=Path,
        help="JSON file with model/revision/precision, devices[{usable_bytes,capacity_basis,memory_kind}], "
             "assignments by placement, optional total_layers/layer_ranges, and "
             "and components[{name,placement,owns,weight_bytes,kv_cache_bytes,"
             "temporary_headroom_bytes,budget_basis}]")
    args = parser.parse_args(argv)
    try:
        if args.command == "inventory":
            result = collect_inventory()
        else:
            with args.configuration.open(encoding="utf-8") as stream:
                result = plan_fit(json.load(stream))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
