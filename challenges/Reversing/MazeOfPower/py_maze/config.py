# This file is a translation of part of https://github.com/itchyny/maze
# Original source code in Go, licensed under the MIT License.
# Translated to Python by forensicskween for a CTF challenge.


import argparse
import sys
import time
from .maze import Point

class Config:
    def __init__(self, args):
        self.Width = args.width
        self.Height = args.height
        self.Start = Point(*map(int, args.start.split(",")))
        self.Goal = Point(*map(int, args.goal.split(",")))
        self.Interactive = args.interactive
        self.Image = args.image
        self.Scale = args.scale
        self.Solution = args.solution
        self.Format = args.format
        self.Seed = int(args.seed) if args.seed else int(time.time_ns())
        self.Output = open(args.output, 'w') if args.output else sys.stdout

def make_config(argis=None):
    parser = argparse.ArgumentParser(description="Maze generator")
    parser.add_argument("--width", type=int, default=0, help="Width of the maze")
    parser.add_argument("--height", type=int, default=0, help="Height of the maze")
    parser.add_argument("--start", type=str, default="0,0", help="Start coordinate")
    parser.add_argument("--goal", type=str, default="", help="Goal coordinate")
    parser.add_argument("--interactive", action="store_true", help="Play the maze interactively")
    parser.add_argument("--solution", action="store_true", help="Show solution path")
    parser.add_argument("--format", choices=["default", "color"], default="default", help="Output format")
    parser.add_argument("-o", "--output", type=str, default="", help="Output file name")
    parser.add_argument("--image", action="store_true", help="Generate image")
    parser.add_argument("--scale", type=int, default=1, help="Image scale")
    parser.add_argument("--seed", type=str, default="", help="Random seed")

    if argis:
        args = parser.parse_args(args=argis)
    else:
        args = parser.parse_args()

    if args.goal == "":
        args.goal = f"{args.height - 1},{args.width - 1}"

    return Config(args)
