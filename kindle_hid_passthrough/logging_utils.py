#!/usr/bin/env python3
"""
Unified Logging Utilities

Provides consistent logging with timestamps, delta tracking,
and colored output for the BLE HID system.

Author: Lucas Zampieri <lzampier@redhat.com>
"""

import logging
import time
from typing import Optional

# Try to import Bumble colors, fall back to no-op if not available
try:
    from bumble.colors import color as bumble_color
except ImportError:
    def bumble_color(text, _color):
        return text

__all__ = ['log', 'color', 'setup_logging', 'setup_daemon_logging']


def color(text: str, color_name: str) -> str:
    """Apply color to text using Bumble's color utility"""
    return bumble_color(text, color_name)


class BLELogger:
    """Logger with automatic timestamps and delta tracking for >>> markers"""

    def __init__(self, name: str = 'ble_hid'):
        self.logger = logging.getLogger(name)
        self._last_timestamp: Optional[float] = None
        self._console_output = True  # Also print to console

    def set_console_output(self, enabled: bool):
        """Enable/disable console output (for daemon mode)"""
        self._console_output = enabled

    def _format_timestamp(self) -> str:
        """Format timestamp with delta from last log"""
        current = time.time()

        if self._last_timestamp is None:
            delta_str = ""
        else:
            delta = current - self._last_timestamp
            delta_str = f" (+{delta:.3f}s)"

        self._last_timestamp = current
        timestamp_str = time.strftime("%H:%M:%S", time.localtime(current))

        return f"[{timestamp_str}]{delta_str}"

    def info(self, msg: str, highlight: bool = False):
        """Log info message with optional highlighting"""
        formatted = f"{self._format_timestamp()} >>> {msg}"
        self.logger.info(msg)

        if self._console_output:
            if highlight:
                print(color(formatted, 'green'))
            else:
                print(formatted)

    def success(self, msg: str):
        """Log success message (green)"""
        formatted = f"{self._format_timestamp()} >>> {msg}"
        self.logger.info(msg)

        if self._console_output:
            print(color(formatted, 'green'))

    def warning(self, msg: str):
        """Log warning message (yellow)"""
        formatted = f"{self._format_timestamp()} >>> {msg}"
        self.logger.warning(msg)

        if self._console_output:
            print(color(formatted, 'yellow'))

    def error(self, msg: str):
        """Log error message (red)"""
        formatted = f"{self._format_timestamp()} >>> {msg}"
        self.logger.error(msg)

        if self._console_output:
            print(color(formatted, 'red'))

    def debug(self, msg: str):
        """Log debug message (cyan)"""
        formatted = f"{self._format_timestamp()} >>> {msg}"
        self.logger.debug(msg)

        if self._console_output and self.logger.isEnabledFor(logging.DEBUG):
            print(color(formatted, 'cyan'))

    def detail(self, msg: str):
        """Log detail message without timestamp (cyan, indented)"""
        self.logger.info(msg)

        if self._console_output:
            print(color(f"    {msg}", 'cyan'))

    def raw(self, msg: str):
        """Print raw message without formatting"""
        if self._console_output:
            print(msg)


def setup_logging(debug: bool = False):
    """Setup logging for interactive/CLI use"""
    log_level = logging.DEBUG if debug else logging.INFO

    # Only configure if not already configured
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s %(levelname)s %(name)s: %(message)s'
        )

    # Set log level on our logger
    logging.getLogger('ble_hid').setLevel(log_level)


def setup_daemon_logging(log_file: str):
    """Setup logging for daemon mode (file only, no console)"""
    root_logger = logging.getLogger()

    # Remove all existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create file handler
    file_handler = logging.FileHandler(log_file)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    root_logger.setLevel(logging.INFO)

    # Silence verbose Bumble library logs
    logging.getLogger('bumble').setLevel(logging.WARNING)

    # Disable console output for our logger
    log.set_console_output(False)


# Global logger instance
log = BLELogger()
