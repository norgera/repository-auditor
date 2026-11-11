from .s1_dyff import DyffAdapter
from .s2_gitleaks import GitleaksAdapter
from .s3_trivy import TrivyAdapter
from .s4_zizmor import ZizmorAdapter
from .s5_osv import OsvAdapter
from .s6_test import TestAdapter

ADAPTERS = {a.id: a for a in (DyffAdapter, GitleaksAdapter, TrivyAdapter, ZizmorAdapter, OsvAdapter, TestAdapter)}
PORTS = {"s1": 8711, "s2": 8712, "s3": 8713, "s4": 8714, "s5": 8715, "s6": 8716}
