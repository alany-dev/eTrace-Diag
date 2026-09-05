"""Detection package — Model 1 detectors.

Importing this package registers all detectors into
`alg_models.detection.base.DETECTOR_REGISTRY`.
"""

from . import base, edge_cascade, event_branch, fits_adapter, streaming, time_rcd_fuse  # noqa: F401
from .base import DETECTOR_REGISTRY, Detector, FeedbackError, get_detector, register_detector
from .edge_cascade import EdgeCascadeDetector
from .fits_adapter import FITSDetector
from .streaming import StreamingRobustDetector
from .time_rcd_fuse import TimeRCDFuseDetector

__all__ = [
    "DETECTOR_REGISTRY",
    "Detector",
    "FeedbackError",
    "get_detector",
    "register_detector",
    "EdgeCascadeDetector",
    "FITSDetector",
    "StreamingRobustDetector",
    "TimeRCDFuseDetector",
]