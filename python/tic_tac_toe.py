import random

# Initialize the board
def initialize_board():
    return [[' ' for _ in range(4)] for _ in range(4)]

# Print the board
def print_board(board):
    for row in board:
        print('|'.join(row))
        print('-' * 7)

# Check if the board is full
def is_board_full(board):
    for row in board:
        if ' ' in row:
            return False
    return True

# Check for a win
def check_win(board, player):
    # Check rows
    for row in board:
        if all([cell == player for cell in row]):
            return True

    # Check columns
    for col in range(4):
        if all([board[row][col] == player for row in range(4)]):
            return True

    # Check diagonals
    if all([board[i][i] == player for i in range(4)]) or all([board[i][3 - i] == player for i in range(4)]):
        return True

    return False

# Get available moves
def get_available_moves(board):
    return [(r, c) for r in range(4) for c in range(4) if board[r][c] == ' ']

# Heuristic evaluation function
def evaluate(board):
    if check_win(board, 'O'):
        return 10
    elif check_win(board, 'X'):
        return -10
    else:
        return 0

# Minimax algorithm with alpha-beta pruning and depth limit
def minimax(board, depth, is_maximizing, alpha, beta, max_depth):
    score = evaluate(board)
    
    if abs(score) == 10 or depth == max_depth or is_board_full(board):
        return score
    
    if is_maximizing:
        max_eval = -float('inf')
        for (r, c) in get_available_moves(board):
            board[r][c] = 'O'
            eval = minimax(board, depth + 1, False, alpha, beta, max_depth)
            board[r][c] = ' '
            max_eval = max(max_eval, eval)
            alpha = max(alpha, eval)
            if beta <= alpha:
                break
        return max_eval
    else:
        min_eval = float('inf')
        for (r, c) in get_available_moves(board):
            board[r][c] = 'X'
            eval = minimax(board, depth + 1, True, alpha, beta, max_depth)
            board[r][c] = ' '
            min_eval = min(min_eval, eval)
            beta = min(beta, eval)
            if beta <= alpha:
                break
        return min_eval

# Find best move for the computer
def find_best_move(board, max_depth):
    best_move = None
    best_value = -float('inf')
    for (r, c) in get_available_moves(board):
        board[r][c] = 'O'
        move_value = minimax(board, 0, False, -float('inf'), float('inf'), max_depth)
        board[r][c] = ' '
        if move_value > best_value:
            best_move = (r, c)
            best_value = move_value
    return best_move

# Main game loop
def play_game():
    board = initialize_board()
    print("Welcome to 4x4 Tic Tac Toe!")
    print_board(board)

    while True:
        # Human move
        while True:
            try:
                row = int(input("Enter the row (0-3): "))
                col = int(input("Enter the column (0-3): "))
                if board[row][col] == ' ':
                    board[row][col] = 'X'
                    break
                else:
                    print("This cell is already occupied!")
            except (ValueError, IndexError):
                print("Invalid input! Please enter row and column numbers between 0 and 3.")

        print_board(board)

        if check_win(board, 'X'):
            print("Congratulations! You win!")
            break
        if is_board_full(board):
            print("It's a draw!")
            break

        # Computer move
        print("Computer is making a move...")
        (comp_row, comp_col) = find_best_move(board, max_depth=3)
        board[comp_row][comp_col] = 'O'
        print_board(board)

        if check_win(board, 'O'):
            print("Computer wins! Better luck next time.")
            break
        if is_board_full(board):
            print("It's a draw!")
            break

play_game()
