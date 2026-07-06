# -*- coding: utf-8 -*-

import sys
import os
import json
import inspect
import logging
import traceback


class FlowLauncher:
    """
    Base class for Flow Launcher Python plugins (modern and safe version)
    """

    def __init__(self):
        # Enable strict output: only allow JSON output to stdout
        self._enable_strict_json_output()
        self.debugMessage = ""

        self.rpc_request = {"method": "query", "parameters": []}
        if len(sys.argv) > 1:
            try:
                self.rpc_request = json.loads(sys.argv[1])
            except Exception as e:
                self.debugMessage = f"Request parse error: {e}"

        self._dispatch_request()

    def _enable_strict_json_output(self):
        """
        Disable non-JSON output: prevent plugin from outputting illegal content that might crash Flow Launcher
        """
        sys.stdout = open(os.devnull, "w")  # Disable print()
        sys.stderr = open(os.devnull, "w")  # Disable error output
        logging.getLogger().setLevel(logging.WARNING)
        logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
        self._json_output = sys.__stdout__.buffer  # Preserve original stdout for UTF-8 JSON output

    def _safe_print_json(self, obj):
        try:
            payload = json.dumps(obj, ensure_ascii=True).encode("utf-8") + b"\n"
            self._json_output.write(payload)
            self._json_output.flush()
        except Exception:
            pass  # Silently ignore any output failure

    def _dispatch_request(self):
        method_name = self.rpc_request.get("method", "query")
        params = self.rpc_request.get("parameters", [])
        if not isinstance(params, list):
            params = [params]

        try:
            methods = {
                name: method for name, method in inspect.getmembers(self, predicate=inspect.ismethod)
                if not name.startswith("_")
            }
            if method_name in methods:
                result = self._call_plugin_method(method_name, methods[method_name], params)
            else:
                self.debugMessage = f"Unknown method: {method_name}"
                result = []

        except Exception as e:
            self.debugMessage = f"{e.__class__.__name__}: {str(e)}\n" + traceback.format_exc()
            result = []

        if method_name in ("query", "context_menu", "load_context_menus"):
            self._safe_print_json({
                "result": result,
                "debugMessage": self.debugMessage
            })

    def _call_plugin_method(self, method_name, method, params):
        if method_name == "query":
            result = method(params[0] if params else "")
        elif method_name in ("context_menu", "load_context_menus"):
            result = method(params[0] if params else {})
        else:
            result = method(*params)

        if result is None:
            return []
        if isinstance(result, list):
            return result
        return [result]

    def query(self, param: str = "") -> list:
        """
        Subclasses should override this method to provide search results
        """
        return []

    def context_menu(self, data) -> list:
        """
        Optional context menu entries for results
        """
        return []

    def debug(self, msg: str):
        """
        Set debug message to be shown in Flow Launcher UI
        """
        self.debugMessage = msg
