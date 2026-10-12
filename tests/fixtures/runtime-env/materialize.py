#!/usr/bin/env python3
"""Create a portable fixture locked to explicitly supplied existing build inputs."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

p = argparse.ArgumentParser()
p.add_argument("destination", type=Path)
p.add_argument("--bash", required=True, help="canonical bash store output")
p.add_argument("--coreutils", required=True, help="canonical coreutils store output")
p.add_argument("--system", default="x86_64-linux")
a = p.parse_args()
a.destination.mkdir(parents=True, exist_ok=False)
shutil.copyfile(Path(__file__).with_name("flake.nix"), a.destination / "flake.nix")
(a.destination / "tools").mkdir()
def store_context(path):
    quoted = json.dumps(path)
    return "builtins.appendContext " + quoted + " { " + quoted + " = { path = true; }; }"

(a.destination / "tools" / "flake.nix").write_text("{ outputs = { self }: { bash = " + store_context(a.bash) + "; coreutils = " + store_context(a.coreutils) + "; system = " + json.dumps(a.system) + "; }; }\n")

subprocess.run(["nix", "flake", "lock", "path:" + str(a.destination.resolve())], check=True)
print(a.destination.resolve())
