#!/usr/bin/python

from pwn import *
import string


def parse_blocks(x, n):
    blocks = []
    for i in range(len(x) / n):
        blocks.append(x[i * n:(i + 1) * n])
    return blocks


def pwn_conn(payload):
    context.log_level = 'critical'
    sh = remote('2018shell2.picoctf.com', 33893)
    sh.sendlineafter(': ', payload)
    data = sh.recvall()
    sh.close()
    return parse_blocks(data[:-1], 32)


def padit(message):
    if len(message) % 16 != 0:
        message = message + '0' * (16 - len(message) % 16)
    return message


def main():
    text0 = "Agent,\nGreetings. My situation report is as follows:\n"  # 53
    text1 = "\nMy agent identifying code is: "  # 31
    text2 = ".\nDown with the Soviets,\n006\n"  # 29
    leak_len = 40

    offset = 16 - len(text0) % 16
    guessed_secret = 'picoCTF{@g3nt6_1$_th3_c00l3$t_'

    for i in range(len(guessed_secret), leak_len):
        payload = bytearray(text1[-15:] + guessed_secret)
        payload.append('?')
        for guess in string.printable:
            payload[-1] = guess
            pfix = 16 - i % 16
            data = bytearray('0' * offset + payload[-16:] + '0' * pfix)
            c_blocks = pwn_conn(data)
            chosen_block = c_blocks[4]
            tail = "".join(c_blocks[5:])
            print "> {0} --- {1} --- {2} --- {3}".format(data[offset: offset + 16],
                                                         chosen_block, (chosen_block in tail), guessed_secret)
            if chosen_block in tail:
                guessed_secret += guess
                break
        if guessed_secret == '':
            print '########### ERROR ###########'
            return
        if guessed_secret[-1] == '}':
            break
    print "All guessed bytes: " + guessed_secret


if __name__ == "__main__":
    main()
