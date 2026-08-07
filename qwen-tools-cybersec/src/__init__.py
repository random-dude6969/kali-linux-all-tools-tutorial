# QwenSec Recon Suite - Python Package Init

"""
QwenSec Recon Suite
~~~~~~~~~~~~~~~~~~~

Professional Cybersecurity Intelligence & Reconnaissance Tool

:copyright: (c) 2024 by Qwen Security Team
:license: MIT, see LICENSE for more details.
"""

from .qwen_recon import (
    QwenReconScanner,
    ScanResult,
    ColorLogger,
    __version__ if hasattr(__import__('sys').modules[__name__], '__version__') else '1.0.0'
)

__author__ = 'Qwen Security Team'
__all__ = [
    'QwenReconScanner',
    'ScanResult',
    'ColorLogger'
]
