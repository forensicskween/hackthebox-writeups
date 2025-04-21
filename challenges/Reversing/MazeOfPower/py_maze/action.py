# This file is a translation of part of https://github.com/itchyny/maze
# Original source code in Go, licensed under the MIT License.
# Translated to Python by forensicskween for a CTF challenge.

from .rand import Seed
from .maze import Maze
import sys

def create_maze(config):
    Seed(config.Seed)
    maze = Maze(config.Height, config.Width)
    maze.Start = config.Start
    maze.Goal = config.Goal
    maze.Cursor = config.Start
    maze.Generate()
    if config.Solution:
        maze.Solve()
    return maze

def action(config):
    maze = create_maze(config)
    if config.Interactive:
        print("Interactive mode is not implemented yet in this translation.")
        # You could implement using curses or similar libraries
    else:
        if config.Image:
            print("Image generation not implemented.")
        else:
            print_maze(maze, config.Output, config.Format)

def print_maze(maze, output, format_type):
    for row in maze.Directions:
        print("".join(f"{cell:04x} " for cell in row), file=output)
