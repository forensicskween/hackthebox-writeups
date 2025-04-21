# This file is a translation of part of https://github.com/itchyny/maze
# Original source code in Go, licensed under the MIT License.
# Translated to Python by forensicskween for a CTF challenge.


from .rand import Int
import operator
import sys

# Maze cell configurations
Up = 1 << 0
Down = 1 << 1
Left = 1 << 2
Right = 1 << 3

SolutionOffset = 4
VisitedOffset = 8

Directions = [Up, Down, Left, Right]

dx = {Up: -1, Down: 1, Left: 0, Right: 0}
dy = {Up: 0, Down: 0, Left: -1, Right: 1}

Opposite = {Up: Down, Down: Up, Left: Right, Right: Left}

keyDirs = {Up:'k',Down:'j',Left:'h',Right:'l'}
keyDirs_inv = {v:k for k,v in keyDirs.items()}

class Point:
    def __init__(self, x, y):
        self.X = x
        self.Y = y

    def Equal(self, target):
        return self.X == target.X and self.Y == target.Y

    def Advance(self, direction):
        return Point(self.X + dx[direction], self.Y + dy[direction])


class Maze:
    def __init__(self, height, width):
        self.Directions = [[0 for _ in range(width)] for _ in range(height)]
        self.Height = height
        self.Width = width
        self.Start = Point(0, 0)
        self.Goal = Point(height - 1, width - 1)
        self.Cursor = Point(0, 0)
        self.Solved = False
        self.Started = False
        self.Finished = False
        self.solution_steps = []

    def Contains(self, point):
        return 0 <= point.X < self.Height and 0 <= point.Y < self.Width

    def Neighbors(self, point):
        neighbors = []
        for direction in Directions:
            next_point = point.Advance(direction)
            if self.Contains(next_point) and self.Directions[next_point.X][next_point.Y] == 0:
                neighbors.append(direction)
        return neighbors

    def Connected(self, point, target):
        direct = self.Directions[point.X][point.Y]
        for direction in Directions:
            if direct & direction != 0:
                next_point = point.Advance(direction)
                if next_point.X == target.X and next_point.Y == target.Y:
                    return True
        return False


    def Next(self, point):
        neighbors = self.Neighbors(point)
        if not neighbors:
            return None
        direction = neighbors[Int()%len(neighbors)]
        self.Directions[point.X][point.Y] |= direction
        next_point = point.Advance(direction)
        self.Directions[next_point.X][next_point.Y] |= Opposite[direction]
        return next_point

    def Generate(self):
        point = self.Start
        stack = [point]
        while stack:
            while True:
                next_point = self.Next(point)
                if not next_point:
                    break
                point = next_point
                stack.append(point)
            i = Int() % ((len(stack) + 1) // 2)
            point = stack[i]
            stack.pop(i)


    def Solve(self):
        if self.Solved:
            return
        point = self.Start
        stack = [point]
        solution = [point]
        visited = 1 << 12

        while not point.Equal(self.Goal):
            self.Directions[point.X][point.Y] |= visited
            for direction in Directions:
                if self.Directions[point.X][point.Y] & direction == direction:
                    next_point = point.Advance(direction)
                    if self.Directions[next_point.X][next_point.Y] & visited == 0:
                        stack.append(next_point)
            point = stack.pop()
            while not self.Connected(point, solution[-1]):
                solution.pop()
            solution.append(point)

        for i, point in enumerate(solution[:-1]):
            next_point = solution[i + 1]
            for direction in Directions:
                if self.Directions[point.X][point.Y] & direction == direction:
                    temp = point.Advance(direction)
                    if next_point.X == temp.X and next_point.Y == temp.Y:
                        self.Directions[point.X][point.Y] |= direction << SolutionOffset
                        self.Directions[next_point.X][next_point.Y] |= Opposite[direction] << SolutionOffset
                        self.solution_steps.append(keyDirs[direction])
                        break
        self.Solved = True

    def Clear(self):
        all_flags = Up | Down | Left | Right
        all_flags |= all_flags << VisitedOffset
        for x in range(self.Height):
            for y in range(self.Width):
                self.Directions[x][y] &= all_flags
        self.Solved = False

    def Move(self, direction):
        point = self.Cursor
        next_point = point.Advance(direction)
        if self.Contains(next_point) and self.Directions[point.X][point.Y] & direction == direction:
            self.Directions[point.X][point.Y] = operator.xor(self.Directions[point.X][point.Y],direction << VisitedOffset)
            self.Directions[next_point.X][next_point.Y] = operator.xor(self.Directions[next_point.X][next_point.Y],Opposite[direction] << VisitedOffset)
            self.Cursor = next_point
        self.Started = True
        self.Finished = self.Cursor.Equal(self.Goal)

    def Undo(self):
        point = self.Cursor
        next_point = point
        while True:
            for direction in Directions:
                if (self.Directions[point.X][point.Y] >> VisitedOffset) & direction != 0:
                    next_point = point.Advance(direction)
                    self.Directions[point.X][point.Y] = operator.xor(self.Directions[point.X][point.Y],direction << VisitedOffset)
                    self.Directions[next_point.X][next_point.Y] = operator.xor(self.Directions[next_point.X][next_point.Y],Opposite[direction] << VisitedOffset)
                    break
            if point.Equal(next_point):
                break
            point = next_point
            count = 0
            for direction in Directions:
                if self.Directions[next_point.X][next_point.Y] & direction != 0:
                    count += 1
            if count > 2:
                break
        self.Cursor = point
        self.Finished = self.Cursor.Equal(self.Goal)

    def __str__(self, format=None):
        if format is None:
            format = Default

        from io import StringIO
        sb = StringIO()

        solved = (Up | Down | Left | Right) << SolutionOffset
        visited = (Up | Down | Left | Right) << VisitedOffset

        # Dynamic format resolution
        startLeft = format.SolutionStartLeft if self.Solved else (
            format.VisitedStartLeft if self.Started else format.StartLeft)
        startRight = format.SolutionStartRight if self.Solved else (
            format.VisitedStartRight if self.Started else format.StartRight)
        goalLeft = format.SolutionGoalLeft if self.Solved else (
            format.VisitedGoalLeft if self.Finished else format.GoalLeft)
        goalRight = format.SolutionGoalRight if self.Solved else (
            format.VisitedGoalRight if self.Finished else format.GoalRight)

        sb.write("\n")
        for x, row in enumerate(self.Directions):
            for direction in [Up, Right]:
                sb.write(format.Path)  # left margin

                # Left wall cell
                if self.Start.X == x and self.Start.Y == 0 and direction == Right:
                    sb.write(startLeft)
                elif self.Goal.X == x and self.Goal.Y == 0 and self.Width > 1 and direction == Right:
                    sb.write(goalLeft)
                else:
                    sb.write(format.Wall)

                for y, cell in enumerate(row):
                    # Inner maze cells (direction == Right: draw floor/cursor/etc.)
                    if direction == Right:
                        if cell & solved:
                            sb.write(format.Solution)
                        elif cell & visited:
                            if self.Cursor.X == x and self.Cursor.Y == y:
                                sb.write(format.Cursor)
                            else:
                                sb.write(format.Visited)
                        else:
                            sb.write(format.Path)

                    # Right-hand or top-wall decorations for edges
                    if self.Start.X == x and self.Start.Y == y and y == self.Width - 1 and y > 0 and direction == Right:
                        sb.write(startRight)
                    elif self.Goal.X == x and self.Goal.Y == y and y == self.Width - 1 and direction == Right:
                        sb.write(goalRight)
                    elif self.Start.X == x and self.Start.Y == y and x == 0 and self.Height > 1 and 0 < y < self.Width - 1 and direction == Up:
                        sb.write(startLeft)
                    elif self.Goal.X == x and self.Goal.Y == y and x == 0 and self.Height > 1 and 0 < y < self.Width - 1 and direction == Up:
                        sb.write(goalLeft)
                    # Maze path
                    elif cell & direction:
                        if (cell >> SolutionOffset) & direction:
                            sb.write(format.Solution)
                        elif (cell >> VisitedOffset) & direction:
                            sb.write(format.Visited)
                        else:
                            sb.write(format.Path)
                    else:
                        sb.write(format.Wall)

                    # Wall cell in Up direction
                    if direction == Up:
                        sb.write(format.Wall)
                sb.write("\n")

        # Bottom wall
        sb.write(format.Path)
        sb.write(format.Wall)
        for y in range(self.Width):
            if self.Start.X == self.Height - 1 and self.Start.Y == y and self.Height > 1 and 0 < y < self.Width - 1:
                sb.write(startLeft)
            elif self.Goal.X == self.Height - 1 and self.Goal.Y == y and 0 < y < self.Width - 1:
                sb.write(goalRight)
            else:
                sb.write(format.Wall)
            sb.write(format.Wall)
        sb.write("\n\n")

        return sb.getvalue()



    def Print(self, output=sys.stdout, format=None):
        print(self.__str__(format), file=output)



class Format:
    def __init__(self, **kwargs):
        self.Wall = kwargs.get("Wall", "##")
        self.Path = kwargs.get("Path", "  ")
        self.StartLeft = kwargs.get("StartLeft", "S ")
        self.StartRight = kwargs.get("StartRight", " S")
        self.GoalLeft = kwargs.get("GoalLeft", "G ")
        self.GoalRight = kwargs.get("GoalRight", " G")
        self.Solution = kwargs.get("Solution", "::")
        self.SolutionStartLeft = kwargs.get("SolutionStartLeft", "S:")
        self.SolutionStartRight = kwargs.get("SolutionStartRight", ":S")
        self.SolutionGoalLeft = kwargs.get("SolutionGoalLeft", "G:")
        self.SolutionGoalRight = kwargs.get("SolutionGoalRight", ":G")
        self.Visited = kwargs.get("Visited", "..")
        self.VisitedStartLeft = kwargs.get("VisitedStartLeft", "S.")
        self.VisitedStartRight = kwargs.get("VisitedStartRight", ".S")
        self.VisitedGoalLeft = kwargs.get("VisitedGoalLeft", "G.")
        self.VisitedGoalRight = kwargs.get("VisitedGoalRight", ".G")
        self.Cursor = kwargs.get("Cursor", "::")


# Default format
Default = Format(
    Wall="##",
    Path="  ",
    StartLeft="S ",
    StartRight=" S",
    GoalLeft="G ",
    GoalRight=" G",
    Solution="::",
    SolutionStartLeft="S:",
    SolutionStartRight=":S",
    SolutionGoalLeft="G:",
    SolutionGoalRight=":G",
    Visited="..",
    VisitedStartLeft="S.",
    VisitedStartRight=".S",
    VisitedGoalLeft="G.",
    VisitedGoalRight=".G",
    Cursor="::",
)

# Color format
Color = Format(
    Wall="\x1b[7m  \x1b[0m",
    Path="  ",
    StartLeft="S ",
    StartRight=" S",
    GoalLeft="G ",
    GoalRight=" G",
    Solution="\x1b[44;1m  \x1b[0m",
    SolutionStartLeft="\x1b[44;1mS \x1b[0m",
    SolutionStartRight="\x1b[44;1m S\x1b[0m",
    SolutionGoalLeft="\x1b[44;1mG \x1b[0m",
    SolutionGoalRight="\x1b[44;1m G\x1b[0m",
    Visited="\x1b[42;1m  \x1b[0m",
    VisitedStartLeft="\x1b[42;1mS \x1b[0m",
    VisitedStartRight="\x1b[42;1m S\x1b[0m",
    VisitedGoalLeft="\x1b[42;1mG \x1b[0m",
    VisitedGoalRight="\x1b[42;1m G\x1b[0m",
    Cursor="\x1b[43;1m  \x1b[0m",
)



def get_solution_keys(maze):
    if not maze.Solved:
        raise ValueError("Maze must be solved before tracing solution keys.")
    mapped_maze = {'S:':-1,'::':1,'##':2,'  ':0,':G':-1}

    str_maze = str(maze)
    maze_strip = [x.strip() for x in (str_maze).strip().split('\n')]
    maze_strip = maze_strip[1:-1]
    maze_strip = [[mapped_maze[x[i:i+2]] for i in range(0,len(x),2)] for x in maze_strip]
    mat = maze_strip
    from collections import deque

    dir_map = {
        (-1, 0): 'k',
        (1, 0): 'j',
        (0, -1): 'h',
        (0, 1): 'l',
    }
    rows = len(maze_strip)
    cols = len(maze_strip[0])

    # Find start (first -1)
    for i in range(rows):
        for j in range(cols):
            if mat[i][j] == -1:
                start = (i, j)
                break
        else:
            continue
        break
    else:
        raise ValueError("Start not found")

    visited = set()
    path = []
    cur = start

    while True:
        visited.add(cur)
        if mat[cur[0]][cur[1]] == -1 and cur != start:
            break  # Reached goal

        for (di, dj), key in dir_map.items():
            ni, nj = cur[0] + di, cur[1] + dj
            if 0 <= ni < rows and 0 <= nj < cols:
                val = mat[ni][nj]
                if (val == 1 or val == -1) and (ni, nj) not in visited:
                    path.append(key)
                    cur = (ni, nj)
                    break
        else:
            raise RuntimeError(f"Dead end at {cur}")

    return path

