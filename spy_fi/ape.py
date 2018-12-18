#!/usr/bin/python

import telnetlib


def parse_blocks(x, n):
    blocks = []
    for i in range(len(x) / n):
        blocks.append(x[i * n:(i + 1) * n])
    return blocks


def tnconn(data):
    tn = telnetlib.Telnet("2018shell.picoctf.com", 33893)
    tn.read_until("Please enter your situation report: ")
    send_string = str(data.decode('ascii') + "\r\n")
    tn.write(send_string)
    challenge = tn.read_all()
    tn.close()
    return challenge


def padit(message):
    if len(message) % 16 != 0:
        message = message + '0' * (16 - len(message) % 16)
    return message


def main():
    text0 = "Agent,\nGreetings. My situation report is as follows:\n"  # 53
    text1 = "\nMy agent identifying code is: "  # 31
    text2 = ".\nDown with the Soviets,\n006\n"  # 29
    # print(len(text0), len(text1), len(text2))
    leak_len = 16

    offset = 16 - len(text0) % 16
    guessed_secret = ''

    for i in range(0, leak_len):
        payload = bytearray(text1[-15:] + guessed_secret)
        payload.append('?')
        for guess in range(0x20, 0x7F):
            payload[-1] = chr(guess)
            pfix = 16 - i % 16
            data = bytearray('0' * offset + payload[-16:] + '0' * pfix)
            res = tnconn(data)
            c_blocks = parse_blocks(res[:-1], 32)
            chosen_block = c_blocks[4]
            tail = "".join(c_blocks[5:])
            print "> {0} --- {1} --- {2} --- {3}".format(data[offset: offset + 16],
                                                         chosen_block, (chosen_block in tail), guessed_secret)
            if chosen_block in tail:
                guessed_secret += chr(guess)
                break
        if guessed_secret == '':
            print '########### ERROR ###########'
            return
    print "All guessed bytes: " + guessed_secret


if __name__ == "__main__":
    main()
