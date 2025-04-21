# This file is a translation of part of https://github.com/itchyny/maze
# Original source code in Go, licensed under the MIT License.
# Translated to Python by forensicskween for a CTF challenge.


from .config import make_config
from .action import action

if __name__ == "__main__":
    config = make_config()
    action(config)
