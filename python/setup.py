from pathlib import Path
from shutil import copy2, copytree

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.sdist import sdist


ROOT = Path(__file__).resolve().parent
SHARED = {
    "securityctl.py": ROOT.parent / "scripts" / "securityctl.py",
    "otel-collector-config.yaml": ROOT.parent / "deploy" / "otel-collector-config.yaml",
}


def shared_source(name):
    # sdists carry a build-time copy; the checkout has exactly one source.
    vendored = ROOT / "_shared" / name
    source = vendored if vendored.is_file() else SHARED[name]
    if not source.is_file():
        raise FileNotFoundError(f"Required shared release input is missing: {name}")
    return source


class Build(build_py):
    def run(self):
        super().run()
        package = Path(self.build_lib) / "securitycontext"
        copy2(shared_source("securityctl.py"), package / "_securityctl.py")
        data = package / "data"
        data.mkdir(exist_ok=True)
        copy2(shared_source("otel-collector-config.yaml"), data / "otel-collector-config.yaml")
        for directory in ("samples", "docs"):
            if (ROOT / directory).is_dir():
                copytree(ROOT / directory, data / directory, dirs_exist_ok=True,
                         ignore=lambda _path, names: [name for name in names if name == "__pycache__" or name.endswith(".pyc")])
        for source in [ROOT / "README.md", ROOT / "README.en.md", *ROOT.glob("constraints*.txt")]:
            if source.is_file():
                copy2(source, data / source.name)


class Source(sdist):
    def make_release_tree(self, base_dir, files):
        super().make_release_tree(base_dir, files)
        shared = Path(base_dir) / "_shared"
        shared.mkdir(exist_ok=True)
        for name in SHARED:
            copy2(shared_source(name), shared / name)


setup(cmdclass={"build_py": Build, "sdist": Source})
