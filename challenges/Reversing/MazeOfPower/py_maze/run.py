# This file is a translation of part of https://github.com/itchyny/maze
# Original source code in Go, licensed under the MIT License.
# Translated to Python by forensicskween for a CTF challenge.


from .main import action
from .config import make_config

def run(args):
    try:
        config = make_config()
        action(config)
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1

if __name__ == "__main__":
    import sys
    exit(run(sys.argv[1:]))
