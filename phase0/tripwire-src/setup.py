from setuptools import setup

# Minimal packaging so `python -m build` produces an sdist that OpenSSF
# package-analysis can ingest via:  scripts/run_analysis.sh -ecosystem pypi -local <sdist>.
setup(
    name="tripwire",
    version="0.0.1",
    packages=["tripwire"],
    description="Synthetic, harmless detonation test sample for Detonator Phase 0",
)
