import subprocess
import sys
import zlib

from pwn import process, remote
from py_maze.action import create_maze
from py_maze.config import make_config


def calc_crc(outres):
    return zlib.crc32(outres)

def get_conn(conn_params):
    if ':' not in conn_params:
        return process(conn_params.split(' '))
    else:
        return remote(*conn_params.split(':'))

def get_powf(powf):
    powf = powf.strip().split(b'work:')[1].decode()
    url_ = powf.split(' | ')[0].strip().split(' ')
    arg_val = powf.split('| ')[1].strip().split(' ')
    result = subprocess.run(
        url_,
        check=True,
        capture_output=True,
        text=True
    )
    output = subprocess.run(
        arg_val,
        input=result.stdout,
        capture_output=True,
        text=True,
        check=True
    )
    return (output.stdout).encode(),result.stdout

def create_maze_args(SEED,HEIGHT=25,WIDTH=50):
    args = f'--height {HEIGHT} --width {WIDTH} --seed {SEED} --solution'.split(' ')
    config = make_config(args)
    maze = create_maze(config)
    return maze,' '.join(['./maze-cli'] + args)

def get_maze_str_solution(maze):
    return maze.__str__().strip(),''.join(maze.solution_steps)

def verify_solutions(MY_MAZE,HIS_MAZE):
    MY_MAZE_LINES = [x.replace('##','  ').strip() for x in MY_MAZE.split('\n')][1:-1]
    HIS_MAZE_LINES = [x.replace('SS','S:').replace('EE',':G').strip() for x in HIS_MAZE.strip().split('\n')]
    assert len(MY_MAZE_LINES) == len(HIS_MAZE_LINES)
    for i in range(len(MY_MAZE_LINES)):
        assert MY_MAZE_LINES[i] ==HIS_MAZE_LINES[i], f"Faulty line at {i}"
    return True


def verify_and_debug(conn_params,DEBUG=False):
    conn = get_conn(conn_params)

    checker = conn.progress('Maze Checker')

    pow_to_solve = conn.recvline()

    result,output = get_powf(pow_to_solve)

    SEED = calc_crc(result)
    
    if DEBUG:
        checker.status(f'This is the output → {output}')

    checker.status(f'This is the result → {result.decode().strip()}')

    checker.status(f'This is the seed → {SEED}')

    maze,arg_cmd = create_maze_args(SEED,25,50)

    checker.status(f"These are the arguments for the maze → {arg_cmd}")

    my_maze_str,solution = get_maze_str_solution(maze)

    if DEBUG:
        checker.status(f"This is the solved maze → \n{my_maze_str}")

    checker.status(f'This is the solution → {solution}')

    conn.sendline(result.strip().decode())

    conn.recvuntil(b'Can you solve my maze within 20 seconds?')

    _ = conn.recvuntil(b'EE')

    checker.status("Asking Server For Solution")

    
    conn.sendline(b'b')

    solution_maze = conn.recvuntil(b'EE')
    HIS_MAZE = solution_maze[solution_maze.find(b'SS'):].decode()

    try:
        verify_solutions(my_maze_str,HIS_MAZE)
        checker.success("We reversed the maze in Python, both mazes match!")
    except:
        checker.failure("Failed to reverse the maze ... Try different arguments")
    conn.close()


def solve_maze(conn_params,DEBUG=False):
    conn = get_conn(conn_params)
    checker = conn.progress('Maze Solver')

    pow_to_solve = conn.recvline()
    result,output = get_powf(pow_to_solve)
    SEED = calc_crc(result)

    if DEBUG:
        checker.status(f'This is the output {output}')

    checker.status(f'This is the result → {result.decode().strip()}')

    checker.status(f'This is the seed → {SEED}')

    maze,arg_cmd = create_maze_args(SEED,25,50)

    checker.status(f"These are the arguments for the maze → {arg_cmd}")

    my_maze_str,solution = get_maze_str_solution(maze)

    if DEBUG:
        checker.status(f"This is the solved maze → \n{my_maze_str}")
        checker.status(f'This is the solution → {solution}')

    conn.sendline(result.strip().decode())

    conn.recvuntil(b'Can you solve my maze within 20 seconds?')

    for step in solution:
        conn.sendline(step.encode())
        _ = conn.recvuntil(b'EE')

    _ = conn.recvuntil(b'Here is your flag:')
    FLAG = conn.recvline().decode().strip()
    print(f'Here is your flag: {FLAG}')
    conn.close()
    return FLAG


if __name__ == "__main__":
    conn_params = sys.argv[1]
    verify_and_debug(conn_params)
    FLAG = solve_maze(conn_params)
    print(FLAG)
    #HTB{w1th_th3_p0w3r_0f_th3_m4z3!!1}
