# This file is a translation of part of https://github.com/itchyny/maze
# Original source code in Go, licensed under the MIT License.
# Translated to Python by forensicskween for a CTF challenge.


import curses
import time
from .maze import Up, Down, Left, Right

key_dirs = {
    curses.KEY_UP: Up,
    curses.KEY_DOWN: Down,
    curses.KEY_LEFT: Left,
    curses.KEY_RIGHT: Right,
    ord('k'): Up,
    ord('j'): Down,
    ord('h'): Left,
    ord('l'): Right,
}

def interactive(maze, fmt):
    def render(stdscr):
        curses.curs_set(0)
        stdscr.nodelay(True)
        start_time = time.time()
        maze.Started = True

        def draw_maze():
            stdscr.clear()
            for i, line in enumerate(str(maze).splitlines()):
                stdscr.addstr(i, 0, line)
            stdscr.refresh()

        def draw_timer():
            duration = time.time() - start_time
            timer = f"{int(duration):8d}.{int((duration * 100) % 100):02d}s"
            stdscr.addstr(maze.Height + 1, 0, timer)
            stdscr.refresh()

        draw_maze()
        while True:
            draw_timer()
            try:
                key = stdscr.getch()
            except:
                continue
            if key == -1:
                continue

            if key in key_dirs and not maze.Finished:
                maze.Move(key_dirs[key])
                if maze.Finished:
                    maze.Solve()
                draw_maze()

            elif key == ord('u') or key == 26:  # Ctrl+Z
                maze.Undo()
                draw_maze()

            elif key == ord('s'):
                if maze.Solved:
                    maze.Clear()
                else:
                    maze.Solve()
                draw_maze()

            elif key in (ord('q'), ord('Q'), 3, 4):  # q, Ctrl+C, Ctrl+D
                break

            time.sleep(0.01)

    curses.wrapper(render)
