"""
Interactive CLI to apply a speed hack to a running process using the `xspeedhack` Python library.

Features:
- Lists running processes and lets you pick by index, name, or PID.
- Attaches to the target process and applies a custom speed factor (like Cheat Engine's speedhack).
- Lets you change the speed on the fly without restarting the program.

Notes:
- Windows only. Attaching to other processes usually requires running the shell as Administrator.
- Requires packages: xspeedhack, psutil, colorama.
"""

from __future__ import annotations

import argparse
import sys
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, List, Optional, Sequence, Tuple

try:
	import psutil  # type: ignore
except Exception as e:  # pragma: no cover - import guard
	print("psutil is required. Install with: pip install psutil", file=sys.stderr)
	raise

try:
	from colorama import Fore, Style, init as colorama_init  # type: ignore
except Exception:  # pragma: no cover - optional pretty output
	class _Fallback:
		RESET_ALL = ""

	class Fore:  # type: ignore
		GREEN = ""
		RED = ""
		CYAN = ""
		YELLOW = ""
		MAGENTA = ""
		BLUE = ""
		WHITE = ""

	class Style:  # type: ignore
		RESET_ALL = ""

	def colorama_init(*_args: Any, **_kwargs: Any) -> None:
		return None


def is_windows() -> bool:
	return os.name == "nt"


def is_admin() -> bool:
	if not is_windows():
		return False
	try:
		import ctypes  # type: ignore

		return bool(ctypes.windll.shell32.IsUserAnAdmin())
	except Exception:
		return False


# A small adapter that tries multiple xspeedhack APIs so this stays compatible across versions.
@dataclass
class SpeedController:
	pid: int
	_impl: Any

	@staticmethod
	def attach(pid: int) -> "SpeedController":
		"""Attach to a process using xspeedhack, trying multiple known API shapes."""
		try:
			import xspeedhack as xsh  # type: ignore
		except Exception as e:
			raise RuntimeError(
				"xspeedhack is not installed. Install with: pip install xspeedhack"
			) from e

		impl: Any = None

		# Try class-based APIs first
		for cls_name in ("Speedhack", "SpeedHack", "Controller", "Engine"):
			cls = getattr(xsh, cls_name, None)
			if cls is not None:
				try:
					impl = cls(pid)
					break
				except Exception:
					pass

		# Try function-based attach/inject
		if impl is None:
			for fn_name in ("attach", "inject", "open", "open_process"):
				fn = getattr(xsh, fn_name, None)
				if callable(fn):
					try:
						impl = fn(pid)
						break
					except Exception:
						pass

		if impl is None:
			# Last-ditch: store pid and hope library exposes global control
			impl = pid

		return SpeedController(pid=pid, _impl=impl)

	def set_speed(self, speed: float) -> None:
		"""Set the speed factor, trying multiple method names."""
		if speed <= 0:
			raise ValueError("Speed must be > 0.0")

		# First try methods on the impl
		for name in (
			"set_speed",
			"SetSpeed",
			"setSpeed",
			"speed",
			"set_multiplier",
			"setMultiplier",
		):
			method = getattr(self._impl, name, None)
			if callable(method):
				method(speed)
				return

		# Try module-level functions with pid
		try:
			import xspeedhack as xsh  # type: ignore
		except Exception:
			raise RuntimeError("xspeedhack import failed unexpectedly")

		for name in (
			"set_speed",
			"setSpeed",
			"speed",
			"SetSpeed",
			"set_multiplier",
		):
			fn = getattr(xsh, name, None)
			if callable(fn):
				try:
					# Prefer function(pid, speed); fall back to function(speed)
					try:
						fn(self.pid, speed)
					except TypeError:
						fn(speed)
					return
				except Exception:
					continue

		raise RuntimeError(
			"Could not find a working method to set speed via xspeedhack."
		)

	def reset(self) -> None:
		"""Reset to 1.0 speed (best effort)."""
		self.set_speed(1.0)


def list_processes(filter_text: Optional[str] = None, limit: int = 200) -> List[psutil.Process]:
	procs: List[psutil.Process] = []
	for p in psutil.process_iter(["pid", "name", "exe"]):
		try:
			name = p.info.get("name") or ""
			exe = p.info.get("exe") or ""
			if filter_text:
				ft = filter_text.lower()
				if ft not in name.lower() and ft not in exe.lower():
					continue
			procs.append(p)
		except (psutil.NoSuchProcess, psutil.AccessDenied):
			continue
	# Sort by name then PID
	procs.sort(key=lambda p: ((p.info.get("name") or "").lower(), p.pid))
	if limit and len(procs) > limit:
		procs = procs[:limit]
	return procs


def print_process_table(procs: Sequence[psutil.Process]) -> None:
	print(f"{Fore.CYAN}#   PID      Name{Style.RESET_ALL}")
	for idx, p in enumerate(procs):
		name = (p.info.get("name") or "").strip()
		print(f"{idx:>3} {p.pid:<8} {name}")


def prompt_select_process(procs: Sequence[psutil.Process]) -> Optional[int]:
	while True:
		raw = input(
			f"Select process by {Fore.YELLOW}index{Style.RESET_ALL} or {Fore.YELLOW}PID{Style.RESET_ALL} (or 'r' to refresh, 'q' to quit): "
		).strip()
		if not raw:
			continue
		if raw.lower() == "q":
			return None
		if raw.lower() == "r":
			return -1
		if raw.isdigit():
			val = int(raw)
			# If it's likely a small index, map to process list
			if 0 <= val < len(procs):
				return procs[val].pid
			# Otherwise treat as PID
			return val
		print(f"{Fore.RED}Invalid input. Try again.{Style.RESET_ALL}")


def interactive_loop(ctrl: SpeedController, initial_speed: float) -> None:
	current_speed = None
	try:
		ctrl.set_speed(initial_speed)
		current_speed = initial_speed
		print(
			f"{Fore.GREEN}Attached to PID {ctrl.pid}. Speed set to {initial_speed}x.{Style.RESET_ALL}"
		)
	except Exception as e:
		print(f"{Fore.RED}Failed to set initial speed: {e}{Style.RESET_ALL}")

	print(
		f"Enter a new speed (e.g., 0.5, 1, 2, 5). Commands: '1' reset, 'q' quit, 'help' show help."
	)

	while True:
		try:
			raw = input(f"[{ctrl.pid}] speed> ").strip()
		except (EOFError, KeyboardInterrupt):
			print()
			break

		if not raw:
			continue
		r = raw.lower()
		if r in ("q", "quit", "exit"):
			break
		if r in ("h", "help", "?"):
			print(
				"Commands:\n"
				"  <number>   Set new speed (e.g., 0.5, 2, 10)\n"
				"  1          Reset to 1.0\n"
				"  q          Quit\n"
			)
			continue
		if r in ("1", "reset"):
			try:
				ctrl.reset()
				current_speed = 1.0
				print(f"{Fore.GREEN}Speed set to 1.0x{Style.RESET_ALL}")
			except Exception as e:
				print(f"{Fore.RED}Failed to reset speed: {e}{Style.RESET_ALL}")
			continue

		# Parse numeric
		try:
			value = float(raw)
			if value <= 0:
				raise ValueError
		except ValueError:
			print(f"{Fore.RED}Invalid speed. Enter a positive number.{Style.RESET_ALL}")
			continue

		try:
			ctrl.set_speed(value)
			current_speed = value
			print(f"{Fore.GREEN}Speed set to {value}x{Style.RESET_ALL}")
		except Exception as e:
			print(f"{Fore.RED}Failed to set speed: {e}{Style.RESET_ALL}")


def pick_and_run(args: argparse.Namespace) -> int:
	if not is_windows():
		print(f"{Fore.RED}This tool currently supports Windows only.{Style.RESET_ALL}")
		return 2

	if not is_admin():
		print(
			f"{Fore.YELLOW}Warning:{Style.RESET_ALL} running without Administrator rights may fail to attach to some processes."
		)

	# If PID provided, skip listing
	pid: Optional[int] = args.pid
	selected_speed: float = args.speed

	while pid is None:
		procs = list_processes(filter_text=args.filter)
		if not procs:
			print(f"{Fore.RED}No processes found matching filter.{Style.RESET_ALL}")
			return 1
		print_process_table(procs)
		choice = prompt_select_process(procs)
		if choice is None:
			return 0
		if choice == -1:
			continue  # refresh
		pid = choice

	# Validate PID exists
	try:
		p = psutil.Process(pid)
		name = p.name()
		print(f"Target: PID {pid} - {name}")
	except Exception:
		print(f"{Fore.RED}PID {pid} not found or not accessible.{Style.RESET_ALL}")
		return 1

	# Attach and set speed
	try:
		ctrl = SpeedController.attach(pid)
	except Exception as e:
		print(f"{Fore.RED}Failed to attach: {e}{Style.RESET_ALL}")
		return 1

	if args.once:
		try:
			ctrl.set_speed(selected_speed)
			print(f"{Fore.GREEN}Speed set to {selected_speed}x{Style.RESET_ALL}")
			return 0
		except Exception as e:
			print(f"{Fore.RED}Failed to set speed: {e}{Style.RESET_ALL}")
			return 1

	# Interactive
	interactive_loop(ctrl, selected_speed)
	return 0


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Apply a speed hack to another process (Windows, via xspeedhack)."
	)
	parser.add_argument(
		"--pid",
		type=int,
		help="PID of the process to attach to. If omitted, you'll be prompted from a list.",
	)
	parser.add_argument(
		"--filter",
		type=str,
		default=None,
		help="Filter process list by substring in name or path.",
	)
	parser.add_argument(
		"--speed",
		type=float,
		default=1.0,
		help="Initial speed factor to apply (e.g., 0.5, 1, 2, 5).",
	)
	parser.add_argument(
		"--once",
		action="store_true",
		help="Set speed once then exit (non-interactive).",
	)
	return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
	colorama_init(autoreset=True)
	args = parse_args(argv)
	try:
		return pick_and_run(args)
	except KeyboardInterrupt:
		print()
		return 130


if __name__ == "__main__":
	raise SystemExit(main())

