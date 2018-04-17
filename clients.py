import socket
import threading
import random
import time

HOST = 'localhost'
PORT = 53

TYPES = ['A', 'NS', 'MX', 'SOA']
DOMAINS = ['darpa.mil', 'twitch.tv', 'google.com', 'anytask.org', 'bbc.com', 'vk.com', 'wolframalpha.com', 'telegram.org', 'seed4.me', 'mail.ru']


def send_req(thread_num):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    for i in range(0, 5):
        type_ = TYPES[random.randint(0, len(TYPES) - 1)]
        domain = DOMAINS[random.randint(0, len(DOMAINS) - 1)]
        client.send((type_ + ' ' + domain).encode())
        d = client.recv(4096).decode(errors='ignore')
        print('!' + 'Thread number {}: request: {}, {}'.format(thread_num, type_, domain), d)
        time.sleep(2)

    client.close()


def main():
    for i in range(1, 25):
        threading.Thread(target=send_req, args=(i, )).start()
        time.sleep(2)


if __name__ == '__main__':
    main()
