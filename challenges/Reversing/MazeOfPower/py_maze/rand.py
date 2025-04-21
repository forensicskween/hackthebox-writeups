# This file is a translation of part of https://github.com/itchyny/maze
# Original source code in Go, licensed under the MIT License.
# Translated to Python by forensicskween for a CTF challenge.


from . import random_rng

# Global RNG instance
_rng = random_rng.GoRNG()

def Seed(value):
    _rng.Seed(value)

def Int():
    return _rng.Int()


