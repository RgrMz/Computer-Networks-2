#!/usr/bin/python3
# -*- coding: utf-8; mode: python -*-

import socket
import hashlib
import sys
import struct 
import base64
import _thread
import urllib.request
import threading


###################             COMMON FUNCTIONS            ###################

def connect_at_TCP_server(node, port):

    clientTCP = socket.socket()
    clientTCP.connect((node, port))
    return clientTCP


def receive_data(sock, ending):
    
    data = bytes()
    keep_receiving = True
    while keep_receiving:
        data_received = sock.recv(32)
        data += data_received
        if bytes(ending, encoding='utf-8') in data_received:
            keep_receiving = False
    return data

def get_next_challenge_identifier(current_challenge_instructions):
    return current_challenge_instructions.decode().partition('\n')[0].partition(':')[2]

def receive_until_timeout(sock):
    
    sock.settimeout(1)
    bin_data = bytearray()
    try:
        while True:
            bin_data += sock.recv(1024)
    except socket.timeout:
        print('All data has been received!')
    sock.settimeout(None)    #Dissabling timeouts on sockets operations for this object
    return bin_data

####################            SPECIFIC CHALLENGE 3 FUNCTIONS         ###############

def checkPalindrome(text_received):

    text_as_list = text_received.decode().split() 
    palindrome = word_as_list = ''
    for word in text_as_list:
        if word.isdigit() or len(word) == 1:  
            continue
        else:
            word_as_list = list(word)
            text_as_list = word_as_list.copy()  
            text_as_list.reverse()  
            palindrome_found = (word_as_list == text_as_list)
            if palindrome_found:
                palindrome = word
                break
    return palindrome


def invert_word(word):

    word_list = list(word)
    word_list.reverse()
    return ''.join(word_list)


def get_before_palindrome(data, palindrome):

    data_list = data.decode().split()
    while data_list.pop() != palindrome:
        pass
    return data_list


####################            SPECIFIC CHALLENGE 5 FUNCTIONS         ###############
# Copyright (C) 2009-2020  David Villa Alises

def sum16(data):
    if len(data) % 2:
        data = b'\0' + data

    return sum(struct.unpack('!%sH' % (len(data) // 2), data))


def cksum(data):
    sum_as_16b_words  = sum16(data)
    sum_1s_complement = sum16(struct.pack('!L', sum_as_16b_words))
    _1s_complement    = ~sum_1s_complement & 0xffff
    return _1s_complement


####################            CHALLENGES SOLVING FUNCTIONS         ###############

def solve_challenge0():

    sock = connect_at_TCP_server('node1', 2000)
    print(sock.recv(1024).decode())
    sock.send('ruben.grande'.encode())
    challenge1_instructions = sock.recv(1024)
    print(challenge1_instructions.decode())
    identifier = challenge1_instructions.decode().partition('\n')[0]  
    sock.close()

    solve_challenge1(identifier)


def solve_challenge1(identifier):

    myUDPServer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    myUDPServer.bind(('', 40976))
    myUDPServer.sendto(('40976 '+identifier).encode(), ('node1', 3000))
    challenge2_instructions, server = myUDPServer.recvfrom(1024)
    print(challenge2_instructions.decode())
    
    identifier2 = get_next_challenge_identifier(challenge2_instructions)

    solve_challenge2(identifier2)


def solve_challenge2(identifier2):
    
    clientTCP = connect_at_TCP_server('node1', 4001)
    data = receive_data(clientTCP, ' 0 ')
    numbers = data.decode().split()
    cont = 0
    for number in numbers:
        if int(number) == 0:
            break
        else:
            cont += 1
    message = str(identifier2 + ' ' + str(cont))
    clientTCP.sendall(message.encode())
    clientTCP.recv(256)
    challenge3_instructions = receive_data(clientTCP, '>')
    print(challenge3_instructions.decode())
    clientTCP.close()
    
    identifier3 = get_next_challenge_identifier(challenge3_instructions)
    
    solve_challenge3(identifier3)


def solve_challenge3(identifier3):

    clientTCP = connect_at_TCP_server('node1', 6000)
    data = bytes()
    index = 0
    final_list = []
    palindrome = ''
    while True:
        received = clientTCP.recv(1024)
        data += received
        palindrome = checkPalindrome(data)
        if palindrome != '':
            print('Palindrome is : ', palindrome, '\n')
            final_list = get_before_palindrome(data, palindrome)
            break
    for word in final_list:
        if word.isdigit():
            pass
        else:
            final_list[index] = invert_word(word)
        index += 1
    message = ' '.join(final_list)
    clientTCP.sendall(' '.join(final_list).encode())
    clientTCP.sendall(('--'+identifier3+'--').encode())
    challenge4_instructions = receive_data(clientTCP, '>')
    print(challenge4_instructions.decode())
    clientTCP.close()
    
    identifier4 = get_next_challenge_identifier(challenge4_instructions)

    solve_challenge4(identifier4)

def solve_challenge4(identifier4):

    clientTCP = connect_at_TCP_server('node1', 10001)
    clientTCP.sendall(identifier4.encode())
    bin_data = receive_until_timeout(clientTCP)
    # Removing the size of the bin file encoded in ASCII
    for element in bin_data:
        if bin_data.pop(0) == ord(':'): break
    sha_sum = hashlib.sha1(bin_data)
    clientTCP.sendall(sha_sum.digest())
    challenge5_instructions = receive_data(clientTCP,'>')
    print(challenge5_instructions.decode())
    clientTCP.close()
    
    identifier5 = get_next_challenge_identifier(challenge5_instructions)
    
    solve_challenge5(identifier5)
    
def solve_challenge5(identifier5):

    clientUDP = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    base64_id = base64.b64encode(bytes(identifier5, encoding='utf-8'))
    message = struct.pack('!3sbhH%ds' % len(base64_id),b'WYP', 0, 0, 0, base64_id)
    checksum = cksum(message)
    message = struct.pack('!3sbhH%ds' % len(base64_id), b'WYP', 0, 0, checksum, base64_id)
    clientUDP.sendto(message, ('node1',7001))
    reply = clientUDP.recv(2048)
    WYP_reply = struct.unpack('!3sbHH%ds' % (len(reply)-8), reply)
    challenge6_instructions = base64.b64decode(WYP_reply[4])    #Decoding reply's payload
    print(challenge6_instructions.decode())
    clientUDP.close()
    
    identifier6 = get_next_challenge_identifier(challenge6_instructions)
    
    solve_challenge6(identifier6)

def solve_challenge6(identifier6):
    
    sender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)      #Communication with node1
    web_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    web_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    web_server.bind(('',50000))
    sender.connect(('node1',8003))
    message = identifier6 + ' 50000'
    sender.sendall(message.encode()) 
    web_server.listen(25)
    try:
        web_server.settimeout(2)
        while True:
            client_connection, client = web_server.accept()
            thread = threading.Thread(target=serve_resource, args=(client_connection,))
            thread.start()
            thread.join()
    except socket.timeout:
        pass
    web_server.close()
    sender.close()

def serve_resource(client_connection, url = 'https://uclm-arco.github.io/ietf-clone/rfc'):
    
    request = client_connection.recv(1024).decode()
    method, resource = request.split(' ')[0] , request.split(' ')[1]
    resource_url = url+resource
    if method == 'POST':
        identifier7 = request.partition('code:')[2].partition('\n')[0]
        print(request.partition('code:')[2])
        solve_challenge7(identifier7)
        return 
    reply_header = "HTTP/1.1 200 OK\r\n" +"Content-Type: text/plain\r\n" +"\r\n"
    url_content = urllib.request.urlopen(resource_url).read()
    HTTP_reply = reply_header.encode("utf-8") + url_content
    client_connection.sendall(HTTP_reply)
    client_connection.close()

def solve_challenge7(identifier7):
    
    final_socket = connect_at_TCP_server('node1', 33333)
    final_socket.sendall(identifier7.encode())
    print(final_socket.recv(1024).decode())
    print('[2020 GYMKANA\'S END!!!!!]')


if __name__ == '__main__':
    solve_challenge0()
