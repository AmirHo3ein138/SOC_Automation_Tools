"""
providers/__init__.py

Provider Interface Definition
-----------------------------
Author: Amirhossein Mousavi

Description:
Defines the 'BaseProvider' abstract class, establishing a strict contract that all 
threat intelligence modules must follow. It mandates the implementation of specific 
lookup methods (IP, Domain, URL, Hash) and requires each provider to declare its 
supported IOC types, ensuring seamless integration with the main application logic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from detector import IOCType
from utils import ProviderResult


class BaseProvider(ABC):
    """Abstract base class defining the common provider interface."""

    name: str = "BaseProvider"

    
    SUPPORTED_TYPES: set[IOCType] = set()

    @abstractmethod
    def lookup_ip(self, ioc: str) -> ProviderResult: ...

    @abstractmethod
    def lookup_domain(self, ioc: str) -> ProviderResult: ...

    @abstractmethod
    def lookup_url(self, ioc: str) -> ProviderResult: ...

    @abstractmethod
    def lookup_hash(self, ioc: str) -> ProviderResult: ...
