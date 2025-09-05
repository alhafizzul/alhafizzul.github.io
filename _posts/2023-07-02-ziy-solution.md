---
title: Cracking a chess engine - ziy by s4r
date: 2023-07-02 09:00:00 +0700
categories: [Writeup, Reverse Engineering]
tags: [crackme]
image:
  path: /commons/2023-07-02-ziy-solution/chess.jpg
---

How to find a good crackme on crackmes.one? The answer is simple: good crackme usually created by skill reverser. [ziy](https://crackmes.one/crackme/614a589733c5d4649c52bbad) for example. I downloaded it 1 year ago but still have no time to try it until now. It takes me about 1 week to solve this.

## Challenge overview
An ELF file which ask user to input 60 characters password. No obfuscation, no anti-debug or anti-disassembler trick but the code is quiet large.

## Reverse engineering part
Clearly this is the hardest part of the challenge. I can not tell the reverse engineering detail here because it would be too long. Instead I will tell some interesting step I did to reverse this.

### Suspicious constant
If you look at function 0x16B5, you will notice that it returns a constant from a global int64_t array. Quickly google some constant (for example `0x1100110A00000000`) lead me to some open source chess engine.
![Google search result](/commons/2023-07-02-ziy-solution/img1.PNG)
By knowning that I am dealing with a chess engine help alot. At least I know how to rename function or struct field correctly.

### Help from open source chess engine
Reading open source chess engine writting in C/C++ (for example [surge](https://github.com/nkarve/surge)) also help. It gives me basic concept how does a chess engine work. Here is a few functions which I was able to reconagize after reading the source.

```c
__int64 __fastcall ziy_get_knight_attack(ziy_t *ziy_obj, int square)
{
  return KNIGHT_ATTACKS[square];
}
```
{: file='Get knight attacks function (0x16B5)'}

```c
__int64 __fastcall ziy_get_pawn_attack(ziy_t *ziy_obj, int pos, int color)
{
  if ( color == WHITE )
    return WHITE_PAWN_ATTACKS[pos];
  else
    return BLACK_PAWN_ATTACKS[pos];
}
```
{: file='Get pawn attacks function (0x1B79)'}

```c
__int64 __fastcall ziy_get_all_attack(ziy_t *ziy_obj, int color)
{
  char king_pos; // [rsp+14h] [rbp-1Ch]
  int i; // [rsp+18h] [rbp-18h]
  int j; // [rsp+1Ch] [rbp-14h]
  int curr_piece; // [rsp+20h] [rbp-10h]
  int chess_piece; // [rsp+24h] [rbp-Ch]
  __int64 moves; // [rsp+28h] [rbp-8h]

  moves = 0LL;
  king_pos = -1;
  for ( i = 0; i <= 63; ++i )
  {
    chess_piece = ziy_obj->chess_board[i];
    if ( (chess_piece == KING || chess_piece == -97) && is_same_color(chess_piece, color) )
      king_pos = i;
  }
  if ( color == WHITE )
    clear_mask(ziy_obj->board_white_mask, king_pos);
  else
    clear_mask(ziy_obj->board_black_mask, king_pos);
  for ( j = 0; j <= 63; ++j )
  {
    curr_piece = ziy_obj->chess_board[j];
    if ( curr_piece && !is_same_color(curr_piece, color) )
    {
      switch ( curr_piece )
      {
        case KNIGHT:
        case 0xFFFFFFE1:
          moves |= ziy_get_knight_attack(ziy_obj, j);
          break;
        case BISHOP:
        case 0xFFFFFFE3:
          moves |= ziy_get_bishop_attack(ziy_obj, j);
          break;
        case KING:
        case 0xFFFFFF9F:
          moves |= ziy_get_king_attack(ziy_obj, j);
          break;
        case QUEEN:
        case 0xFFFFFFAD:
          moves |= ziy_get_queen_attack(ziy_obj, j);
          break;
        case ROOK:
        case 0xFFFFFFC5:
          moves |= ziy_get_rook_attack(ziy_obj, j);
          break;
        case PAWN:
        case 0xFFFFFFEF:
          moves |= ziy_get_pawn_attack(ziy_obj, j, -color);
          break;
      }
    }
  }
  if ( color == WHITE )
    set_board_mask(ziy_obj->board_white_mask, king_pos);
  else
    set_board_mask(ziy_obj->board_black_mask, king_pos);
  return moves;
}
```
{: file='Get attacks of white or black function (0x2805)'}

```c
__int64 __fastcall ziy_is_check(ziy_t *ziy_obj, int color)
{
  char king_pos; // [rsp+14h] [rbp-8h]
  int i; // [rsp+18h] [rbp-4h]

  king_pos = -1;
  for ( i = 0; i <= 63; ++i )
  {
    if ( ziy_obj->chess_board[i] == KING * color )
      king_pos = i;
  }
  if ( color == WHITE )
    return (ziy_obj->all_attacks_to_white_bitmask >> king_pos) & 1;
  else
    return (ziy_obj->all_attacks_to_black_bitmask >> king_pos) & 1LL;
}
```
{: file='Get if the king is checked or not (0x35F3)'}

There are more but I will not show all of them because this post would be too long. By keep reading the source, rename the fields I was able to reconagize most of the code and understand the chess engine better.
### Chess engine struct and define
```c
struct __attribute__((packed)) __attribute__((aligned(4))) ziy_t
{
  int chess_board[64];
  _DWORD color;
  _DWORD present_mask;
  move_t move_table_array[150];
  _DWORD move_cnt;
  int field_268C;
  _QWORD pawn_first_move_mask;
  __int64 board_white_mask;
  __int64 board_black_mask;
  unsigned __int64 all_attacks_to_white_bitmask;
  _QWORD all_attacks_to_black_bitmask;
  _DWORD is_finish;
  _DWORD turn;
  _QWORD hash;
  _DWORD dword26C8;
  _BYTE gap26CC[4788];
  _DWORD dword3980;
};

struct move_t
{
  int chess_piece;
  int from_pos;
  int field_8;
  int to_pos;
  int is_next_pos_have_piece;
  int field_14;
  int is_castling_move;
  int field_1C;
  __int64 field_20;
  int is_en_passant;
  int is_pawn_first_move;
  int not_checkmate_move;
  int field_34;
  __int64 field_38;
};

enum piece_t
{
  PAWN = 0x11,
  BISHOP = 0x1D,
  KNIGHT = 0x1F,
  ROOK = 0x3B,
  QUEEN = 0x53,
  KING = 0x61,
};

enum color_t
{
  WHITE = 0x1,
  BLACK = 0xFFFFFFFF,
};

```
There are still some unknown fields but this is enough for me to understand the crackme.


### The chess AI
The crackme also implement a simple AI.
```c
int __fastcall ziy_ai_move(ziy_t *ziy, _BYTE *move_info)
{
  ziy_get_all_not_check_moves(ziy, ziy->color);
  if ( ziy->move_cnt )
  {
    ziy_extract_move_info(ziy, ziy->move_table_array, move_info);
    ziy_apply_move(ziy, ziy->move_table_array);
    ziy_get_all_not_check_moves(ziy, ziy->color);
    if ( ziy_is_checkmate(ziy, ziy->color) )
    {
      ziy->is_finish = 1;
      ziy->turn = ziy->color;
    }
    else if ( ziy_is_not_checkmate(ziy, ziy->color) )
    {
      ziy->is_finish = 1;
    }
    return 0;
  }
  else
  {
    ziy->is_finish = 1;
    if ( ziy_is_checkmate(ziy, ziy->color) )
      ziy->turn = -ziy->color;
    return 0;
  }
}
```
{: file='Simple chess AI (0x3FD5)'}
The logic of AI is very simple. First, it list all possible moves and store them in `ziy->move_table_array`. Then it take the first move in `ziy->move_table_array` and play it.

### The logic of password checking

```c
unsigned int __fastcall parse_x(char a1)
{
  return a1 - 0x6E;
}

unsigned int __fastcall parse_y(char a1)
{
  return a1 - 0x69;
}

__int64 __fastcall ziy_get_move_from_input(ziy_t *a1, unsigned __int8 *a2, move_t *move)
{
  unsigned int y2; // eax
  unsigned int x1; // [rsp+20h] [rbp-18h]
  unsigned int y1; // [rsp+24h] [rbp-14h]
  unsigned int x2; // [rsp+28h] [rbp-10h]

  x1 = parse_x(*a2);
  y1 = parse_y(a2[1]);
  x2 = parse_x(a2[2]);
  y2 = parse_y(a2[3]);
  move->from_pos = x1 + 8 * y1;
  move->to_pos = x2 + 8 * y2;
  move->field_14 = 0;
  move->is_castling_move = 0;
  move->field_8 = 0;
  return 0LL;
}

int __fastcall ziy_player_move(ziy_t *ziy, unsigned __int8 *input, int move_info)
{
  move_t move; // [rsp+30h] [rbp-50h] BYREF
  unsigned __int64 v6; // [rsp+78h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  memset(&move, 0, sizeof(move));
  if ( ziy->is_finish )
    return 0xFFFFFFFC;
  if ( (unsigned int)ziy_get_move_from_input(ziy, input, &move) )
    return 0xFFFFFFFE;
  ziy_get_all_not_check_moves(ziy, ziy->color);
  if ( (unsigned int)ziy_get_full_player_move(ziy, &move, move_info) )
    return 0xFFFFFFFD;
  ziy_apply_move(ziy, &move);
  ziy_get_all_not_check_moves(ziy, ziy->color);
  if ( ziy_is_checkmate(ziy, ziy->color) )
  {
    ziy->is_finish = 1;
    ziy->turn = ziy->color;
  }
  else if ( ziy_is_not_checkmate(ziy, ziy->color) )
  {
    ziy->is_finish = 1;
  }
  return 0;
}

int __fastcall main(int a1, char **a2, char **a3)
{
  unsigned int seed; // eax
  int is_valid; // [rsp+0h] [rbp-B0h]
  int i; // [rsp+4h] [rbp-ACh]
  ziy_t *ziy_obj; // [rsp+18h] [rbp-98h]
  __int64 data_buffer_array[5]; // [rsp+20h] [rbp-90h]
  _BYTE move_info[10]; // [rsp+49h] [rbp-67h] BYREF
  char dest[12]; // [rsp+53h] [rbp-5Dh] BYREF
  char v11; // [rsp+5Fh] [rbp-51h]
  char input[72]; // [rsp+60h] [rbp-50h] BYREF
  unsigned __int64 v13; // [rsp+A8h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  seed = time(0LL);
  srand(seed);
  data_buffer_array[0] = (__int64)g_board_1;
  data_buffer_array[1] = (__int64)g_board_2;
  data_buffer_array[2] = (__int64)g_board_3;
  data_buffer_array[3] = (__int64)g_board_4;
  data_buffer_array[4] = (__int64)g_board_5;
  is_valid = 1;
  printf("Enter the password: ");
  fgets(input, 70, stdin);
  input[strcspn(input, "\n")] = 0;
  if ( (unsigned int)strlen(input) == 60 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      memcpy(dest, &input[12 * i], sizeof(dest));
      v11 = 0;
      ziy_obj = ziy_create();
      ziy_set_board(ziy_obj, (int *)data_buffer_array[i]);
      if ( ziy_player_move(ziy_obj, (unsigned __int8 *)dest, 1)
        || ziy_ai_move(ziy_obj, move_info)
        || ziy_player_move(ziy_obj, (unsigned __int8 *)&dest[4], 1)
        || ziy_ai_move(ziy_obj, move_info)
        || ziy_player_move(ziy_obj, (unsigned __int8 *)&dest[8], 1)
        || ziy_ai_move(ziy_obj, move_info) )
      {
        puts("error");
        return 0;
      }
      is_valid &= (ziy_obj->turn == WHITE) & ziy_obj->is_finish;
      ziy_free(ziy_obj);
    }
    if ( is_valid )
      printf("Good job! The flag is brb{\%s}\n", input);
    else
      puts("error");
    return 0;
  }
  else
  {
    puts("error");
    return 0;
  }
}
```
Password will be convertered to moves. User plays white and the goal is checkmate the AI in 3 moves. There are total 5 matches user have to win to pass the password check.
![Match 1](/commons/2023-07-02-ziy-solution/img2.PNG)
_Match 1_
![Match 2](/commons/2023-07-02-ziy-solution/img3.PNG)
_Match 2_
![Match 3](/commons/2023-07-02-ziy-solution/img4.PNG)
_Match 3_
![Match 4](/commons/2023-07-02-ziy-solution/img5.PNG)
_Match 4_
![Match 5](/commons/2023-07-02-ziy-solution/img6.PNG)
_Match 5_

## Fighting with chess AI
To fight with chess AI, There are 2 problem need to be solved
- Find a way to interactive with chess match
- Play chess well enough to win the AI in 3 moves

### Playing chess through debugger
My method to solve first problem is writing a script to help me play chess through debugger. By knowning the chess struct and define, I am able to print out the chess board. My script written for IDA debugger but same concept can be applied to other debugger like binary ninja (cheaper alternative) or gdb (free).
```python
import ctypes
import chess
from idautils import *
from idc import *
from idaapi import *

KNIGHT = 31
KING = 97
PAWN = 17
BISHOP = 29
ROOK = 59
QUEEN = 83

def data_to_FENs(data):
    fens = ""
    for i in range(0, 8):
        empty = 0
        line = ""
        for j in range(0, 8):
            c = ctypes.c_long(data[i * 8 + j]).value
            if c == 0:
                empty += 1
            else:
                if c in [KNIGHT, -KNIGHT]:
                    if empty > 0:
                        line += str(empty)
                        empty = 0
                    line += ["N", "n"][[KNIGHT, -KNIGHT].index(c)]
                elif c in [KING, -KING]:
                    if empty > 0:
                        line += str(empty)
                        empty = 0
                    line += ["K", "k"][[KING, -KING].index(c)]
                elif c in [PAWN, -PAWN]:
                    if empty > 0:
                        line += str(empty)
                        empty = 0
                    line += ["P", "p"][[PAWN, -PAWN].index(c)]
                elif c in [BISHOP, -BISHOP]:
                    if empty > 0:
                        line += str(empty)
                        empty = 0
                    line += ["B", "b"][[BISHOP, -BISHOP].index(c)]
                elif c in [ROOK, -ROOK]:
                    if empty > 0:
                        line += str(empty)
                        empty = 0
                    line += ["R", "r"][[ROOK, -ROOK].index(c)]
                elif c in [QUEEN, -QUEEN]:
                    if empty > 0:
                        line += str(empty)
                        empty = 0
                    line += ["Q", "q"][[QUEEN, -QUEEN].index(c)]
                elif c != 0:
                    if empty > 0:
                        line += str(empty)
                        empty = 0
                    line += "?"
                    print(c)
        if empty > 0:
            line += str(empty)
        line += "/"
        fens = line + fens
            
    return fens[:-1]
    
def ida_debug_print_board(ziy_addr):
    data = []
    for i in range(0, 64):
        data.append(get_dword(4 * i + ziy_addr))
    
    fens = data_to_FENs(data)
    print("FENs: %s" % fens)
    board = chess.Board(fens)
    print(board)


if __name__ == "__main__":
    ida_debug_print_board(get_reg_value("rdi"))
```
Run script before crackme call `ziy_player_move` or `ziy_ai_move` will print the chess board. Also by knowing how does input converted to moves, I'm able to writing function to reverse moves to input.
```python
def move_to_input(from_x, from_y, to_x, to_y):
    result = ""
    result += chr(from_x + 0x6E)
    result += chr(from_y + 0x69)
    result += chr(to_x + 0x6E)
    result += chr(to_y + 0x69)
    return result
```
By printing chess board and keep updating my moves to memory through debugger, I am finally able to play chess with AI. I know this is inconvenient but It works .

### Help from stockfish
Second problem can be solved by using stockfish. For anyone who doesn't know stockfish is the best open source chess AI until now. 

### Final solving script
After playing for a while, I am able to record all moves and get the final password.
```python
import ctypes
import chess

KNIGHT = 31
KING = 97
PAWN = 17
BISHOP = 29
ROOK = 59
QUEEN = 83

def move_to_input(from_x, from_y, to_x, to_y):
    result = ""
    result += chr(from_x + 0x6E)
    result += chr(from_y + 0x69)
    result += chr(to_x + 0x6E)
    result += chr(to_y + 0x69)
    return result

if __name__ == "__main__":
    solution_1 = [(6, 1, 6, 6),
                  (6, 6, 3, 3),
                  (3, 3, 1, 3)]
    
    solution_2 = [(0, 0, 5, 5),
                  (4, 6, 5, 7),
                  (7, 5, 5, 6)]
                  
    solution_3 = [(5, 3, 4, 2),
                  (6, 2, 6, 3),
                  (4, 2, 5, 1)]
                  
    solution_4 = [(2, 0, 7, 0),
                  (7, 0, 4, 0),
                  (4, 0, 4, 3)]
                  
    solution_5 = [(4, 5, 5, 6),
                  (7, 4, 7, 3),
                  (7, 3, 4, 3)]
    
    solutions = [solution_1, solution_2, solution_3, solution_4, solution_5]
    
    result = ""
    for solution in solutions:
        for move in solution:
            result += move_to_input(move[0], move[1], move[2], move[3])
    
    print(result.ljust(60, "A"))
```
The correct password is `tjtotoqlqlolnisnrospunsoslrktktlrksjpiuiuiririrlrnsoumululrl`

## Conclusion
1. I was born in a city where people mostly play [chinese chess](https://en.wikipedia.org/wiki/Xiangqi) instead of chess. I have never played chess before until I started solving this crackme.
2. Did I solve this crackme by myself? To be honest I am not. I was stuck for a day because stockfish could not find the solution. Then I pm s4r to ask for hint and he said my parsed chess board is inverted. He also give me a nice [link](https://lichess.org/editor) to play with stockfish. After correct the chess board, stockfish was able to checkmate in 3 moves. Here is my first parsed board (match 1).
![Inverted board](/commons/2023-07-02-ziy-solution/img7.PNG)
_Inverted board_
I still don't know why stockfish can't checkmate in 3 moves for inverted board although it should be the same.