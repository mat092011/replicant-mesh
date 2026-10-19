"""Headless, standard-library-only participant connector foundation."""

from .client import ConsumerClient, LocalManagementClient
from .errors import ConnectorError, FeatureUnavailable

__all__ = ["ConnectorError", "ConsumerClient", "FeatureUnavailable", "LocalManagementClient"]
