#!/usr/bin/python3
# -*- coding: utf-8; mode: python -*-

import socket
import hashlib
import sys
import struct 
import base64
import _thread
import urllib.request


###################             COMMON FUNCTIONS            ###################

def connect_at_TCP_server(node, port):
    '''Connects to a TCP server given by the address (node, port)
       and returns suck socket to be used in the communication 
    '''
    clientTCP = socket.socket()
    clientTCP.connect((node, port))
    return clientTCP


def receive_data(sock, ending):
    ''' Receive data from a socket until token ending is received and detected'''

    data = bytes()
    keep = True
    while keep:
        received = sock.recv(32)
        data += received
        if bytes(ending, encoding='utf-8') in received:
            # Ending has been received, stop receiving data
            keep = False
    return data

####################            SPECIFIC CHALLENGE 3 FUNCTIONS         ###############


def checkPalindrome(string):
    ''' Check if a given string is a palindrome (not considering numbers)'''

    stream = string.decode().split()  # Data received
    aux = ''
    palindrome = ''
    for word in stream:
        if word.isdigit() or len(word) == 1:  # Words of length 1 shouldn't be considered as palindromes
            continue
        else:
            aux = list(word)
            string_as_list = aux.copy()  # Create a copy of the word as a list
            string_as_list.reverse()  # Reverse the list in place
            # Checking if a word is a palindrome
            result_current_stream = (aux == string_as_list)
            if result_current_stream:
                palindrome = word
                break
    return palindrome


def invert_word(word):
    '''Reverses the word passed as argument word'''

    word_list = list(word)
    word_list.reverse()
    return ''.join(word_list)


def get_before_palindrome(data, palindrome):
    '''Builds a list containing all the words and numbers received before the palindrome'''

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

def challenge0():
    '''Solves the challenge 0 ---> Sending e-mail user name'''

    sock = connect_at_TCP_server('node1', 2000)
    print(sock.recv(1024).decode())
    sock.send('ruben.grande'.encode())
    challenge1_instructions = sock.recv(1024)
    print(challenge1_instructions.decode())
    identifier = challenge1_instructions.decode().partition(
        '\n')[0]  # Parte del mensaje a enviar en el reto 1
    sock.close()

    reto1(identifier)


def reto1(identifier):
    '''Solves the challenge 1 ---> UDP server'''

    # Creacion de un socket UDP
    myUDPServer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    myUDPServer.bind(('', 40976))
    myUDPServer.sendto(('40976 '+identifier).encode(), ('node1', 3000))
    challenge2_instructions, server = myUDPServer.recvfrom(1024)
    print(challenge2_instructions.decode())

    # To extract the new identifier, first we take the first line of text with partition('\n') and [0]
    # element to take all the data before the first '\n' found. With a new partition() over this string
    # we take all the data after the token ':' which is the identifier
    identifier2 = challenge2_instructions.decode().partition('\n')[
        0].partition(':')[2]
    myUDPServer.close()

    challenge2(identifier2)


def challenge2(identifier2):
    '''Solves the challenge 2 ---> TCP number counter'''

    clientTCP = connect_at_TCP_server('node1', 4001)
    # Receiving numbers until a single zero ( ' 0 ') is received
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
    # Receving the rest of numbers after 0 is encountered
    # which doesn't have to be read
    clientTCP.recv(256)
    # Receiving all the instructions
    challenge3_instructions = receive_data(clientTCP, '>')
    print(challenge3_instructions.decode())
    identifier3 = challenge3_instructions.decode().partition('\n')[
        0].partition(':')[2]
    clientTCP.close()
    challenge3(identifier3)


def challenge3(identifier3):
    '''Solves the challenge 3 ---> TCP Reverse'''

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
    identifier4 = challenge4_instructions.decode().partition('\n')[
        0].partition(':')[2]
    challenge4(identifier4)
    clientTCP.close()


def challenge4(identifier4):
    
    '''Solves the challenge 4 ---> SHA1'''

    clientTCP = connect_at_TCP_server('node1', 10001)
    clientTCP.sendall(identifier4.encode())
    bin_data = bytearray(clientTCP.recv(1024))
    size = ''
    keep = True
    # Removing the size of the bin file encoded in ASCII
    for bi in bin_data:
        popped = bin_data.pop(0)
        if popped != ord(':'):
            size += chr(popped)
        if popped == ord(':'):
            break
    size_d = sys.getsizeof(bin_data)
    try:
        clientTCP.settimeout(2)
        while True:
            bin_data_recv = clientTCP.recv(int(size))
            bin_data += bin_data_recv
            size_d += sys.getsizeof(bin_data_recv)
    except socket.timeout:
        print('Receiving buffer is finally empty!')
    finally:
        sha_sum = hashlib.sha1(bin_data)
        clientTCP.sendall(sha_sum.digest())
    challenge5_instructions = receive_data(clientTCP,'>')
    print(challenge5_instructions.decode())
    identifier5 = challenge5_instructions.decode().partition('\n')[0].partition(':')[2]
    clientTCP.close()
    challenge5(identifier5)
    
    
def challenge5(identifier5):

    '''Solves the challenge 5 ---> WYP'''

    clientUDP = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    base64_id = base64.b64encode(bytes(identifier5, encoding='utf-8'))
    message = struct.pack('!3sbhH%ds' % len(base64_id),b'WYP', 0, 0, 0, base64_id)
    checksum = cksum(message)
    message = struct.pack('!3sbhH%ds' % len(base64_id), b'WYP', 0, 0, checksum, base64_id)
    clientUDP.sendto(message, ('node1',7001))
    reply = clientUDP.recv(2048)
    challenge6_instructions = struct.unpack('!3sbHH %ds' % (len(reply)-8), reply)
    print(base64.b64decode(challenge6_instructions[4]).decode())
    identifier6 = base64.b64decode(challenge6_instructions[4]).decode().partition('\n')[0].partition(':')[2]
    challenge6(identifier6)
    clientUDP.close()

def challenge6(identifier6):
    
    sender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    web_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    web_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    web_server.bind(('',60000))
    sender.connect(('node1',8003))
    msg = identifier6 + ' ' + '60000'
    sender.sendall(msg.encode()) 
    web_server.listen(25)
    while 1:
        
        child_sock, client = web_server.accept()
        _thread.start_new_thread(handle, (child_sock, client))
        print(sender.recv(1024).decode())
        #print(child_sock, client)
        #handle(child_sock, client)

def handle (child_sock, client, url = 'http://www.ietf.org/rfc'):
    
    request = child_sock.recv(1024).decode()
    print(request)
    resource = request.partition('\n')[0].partition(' ')[2].partition(' ')[0]
    print(resource)
    child_sock.send('HTTP/1.1 200 OK\n'.encode())
    child_sock.send('Content-Type: text/html\n\n'.encode())
    resource_url = url+resource
    print(resource_url)
    url_content = urllib.request.urlopen(resource_url)
    child_sock.send(url_content.read())
    print(child_sock.recv(1024).decode())
    
if __name__ == '__main__':
    challenge0()
