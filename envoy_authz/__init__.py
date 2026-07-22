"""envoy_authz package.

Configures process-wide JSON logging on import so both the gRPC and HTTP
entrypoints emit consistent structured logs.
"""

import logging
import sys

from pythonjsonlogger import json as jsonlogger

_handler = logging.StreamHandler(stream=sys.stdout)
_handler.setFormatter(jsonlogger.JsonFormatter())
logging.basicConfig(level=logging.INFO, handlers=[_handler])
