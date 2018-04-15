import socket
import itertools
import binascii
import io
import threading
import datetime
import time
import pickle

from cache import CacheDict

ID = itertools.count()
SAVE_FILE = 'save.p'


def validate_cache_entry(entry):
    ttl, got_at = entry.ttl, entry.got_at
    expires_after = got_at + datetime.timedelta(seconds=ttl)
    today = datetime.datetime.today()
    return today < expires_after


class DNSServer:
    def __init__(self, host, port, validation_time):
        dict_ = None
        try:
            dict_ = pickle.load(open(SAVE_FILE, "rb"))
        except (EOFError, IOError):
            pass
        self.host = host
        self.port = port
        self.cache = CacheDict(validate_cache_entry, validation_time, back_up_dict=dict_)
        self.cache_dispatcher = self.cache.dispatcher
        self.clients = {}

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.settimeout(2.5)  # TODO: del?
        self.server.listen(10)

    def __del__(self):
        self.cache_dispatcher.stop = True
        CacheDict.lock.acquire()
        with open(SAVE_FILE, 'wb') as f:
            CacheDict.lock.release()
            pickle.dump(self.cache.dict, f)
        self.server.close()

    @staticmethod
    def raise_server(host, port, validation_time):
        server = DNSServer(host, port, validation_time)
        threading.Thread(target=server._accept_conns, args=()).start()

    def _accept_conns(self):
        while True:
            try:
                conn, addr = self.server.accept()
                threading.Thread(target=self._listen, args=(conn, addr)).start()
            except socket.timeout:
                self.__del__()
                break

    def _listen(self, conn, addr):
        try:
            while True:
                data = ''
                # while (not data) and conn: TODO: del?
                data = conn.recv(1024)
                decoded_data = data.decode('utf-8')
                type_, domain = decoded_data.split()
                answer = self.cache[(type_, domain)]
                print('------------------------------------')
                print('Cache: ', self.cache.dict)
                print('------------------------------------')

                if answer:  # TODO: del it
                    print('Cache hit!')

                if not answer:
                    print('Cache miss :(')
                    dns_data = DNSData()
                    answers = dns_data.process_name(type_, domain)
                    self.update_cache(answers)
                    if dns_data.error:
                        conn.sendall(dns_data.error.encode('utf-8'))
                        continue
                    answer = self.cache[(type_, domain)]
                try:
                    conn.sendall(str(answer).encode('utf-8'))
                except TypeError:
                    print('Something went wrong')
                    conn.close()
                    return
        except Exception as e:
            conn.close()
            return

    def update_cache(self, answers):
        for answer in answers:
            self.cache[(answer.type, answer.domain)] = answer

    def exit(self):
        self.server.close()


class DNSEntry:
    def __init__(self, domain, type_, class_, ttl, data):
        self.domain = domain
        self.type = type_
        self.class_ = class_
        self.ttl = ttl
        self.data = data
        self.got_at = datetime.datetime.today()

    def __repr__(self):
        return 'domain: {}, type: {}, ttl: {}, data: {}'.format(self.domain, self.type, self.ttl, self.data)

    def __str__(self):
        return self.__repr__()


class DNSData:
    def __init__(self):
        self.__end = bytes.fromhex('00')
        self.__conf_bits = bytes.fromhex('0100')
        self.__one = bytes.fromhex('0001')
        self.__zero = bytes.fromhex('0000')
        self.query = None
        self.response_data = None
        self.io_response_data = None
        self.header = None
        self.questions_count = None
        self.questions = []
        self.answers_count = None
        self.authority_count = None
        self.additional_count = None
        self.raw_answers = None
        self.error = None
        self.types = {1: 'A', 2: 'NS', 3: 'MD', 15: 'MX', 4: 'MF', 16: 'TXT', 6: 'SOA'}
        self.byte_qtypes = {'A': self.__one, 'NS': bytes.fromhex('0002'),
                            'MD': bytes.fromhex('0003'), 'SOA': bytes.fromhex('0006'),
                            'MX': bytes.fromhex('000F'), 'MF': bytes.fromhex('0004'),
                            'TXT': bytes.fromhex('0010')}
        self.answers = []

    def process_name(self, qtype, domain):
        self._generate_query(qtype, domain)
        self.send_query()
        if self.io_response_data:
            self._parse_response()
        return self.answers

    def __create_entry(self, domain, type_, class_, ttl, rdata):
        class_ = 'IN'

        type_value = int.from_bytes(type_, byteorder='big')
        try:
            qtype = self.types[type_value]
        except KeyError:
            qtype = 'unknown'
        ttl = int.from_bytes(ttl, byteorder='big')
        data = ''
        if qtype == 'A':
            data = '.'.join(map(str, [int.from_bytes(bytes([x]), byteorder='big') for x in rdata]))
        elif qtype in {'NS', 'MD', 'MF'}:
            data = self.__form_domain_name(self.__get_domain_name(io.BytesIO(), io.BytesIO(rdata), 0))
        elif qtype == 'MX':
            io_rdata = io.BytesIO(rdata)
            preference = int.from_bytes(io_rdata.read(2), byteorder='big')
            name = self.__form_domain_name(self.__get_domain_name(io.BytesIO(), io_rdata, 0))
            data = ('Preference: {}'.format(preference), name)
        elif qtype == 'TXT':
            data = rdata.decode('utf-8', errors='ignore')
        elif qtype == 'SOA':
            io_rdata = io.BytesIO(rdata)
            mname = self.__form_domain_name(self.__get_domain_name(io.BytesIO(), io_rdata, 0))
            rname = self.__form_domain_name(self.__get_domain_name(io.BytesIO(), io_rdata, 0))
            serial, refresh, retry, expire, minimum = [int.from_bytes(x, byteorder='big') for x in
                                                       [io_rdata.read(4),
                                                        io_rdata.read(4),
                                                        io_rdata.read(4),
                                                        io_rdata.read(4),
                                                        io_rdata.read(4)]]
            data = 'Primary name server: {}\r\nResponsible authority\'s mailbox:{}\r\nSerial Number: {}\r\n' \
                   'Refresh interval: {}\r\nRetry interval: {}\r\nExpire limit: {}\r\n' \
                   'Minimum TTL: {}'.format(mname, rname, serial, refresh, retry, expire, minimum)

        return DNSEntry(domain, qtype, class_, ttl, data)

    def _generate_query(self, qtype_word, domain_name):
        id_ = binascii.unhexlify(add_padding(hex(next(ID)), '0x', 4)[2:])
        conf_bits = self.__conf_bits
        qdcount, ancount, nscount, arcount = [self.__one] + [self.__zero] * 3
        qname = bytes()
        for label in domain_name.split('.'):
            qname += bytes([len(label)])
            qname += label.encode()
        end = self.__end
        qtype = self.byte_qtypes[qtype_word]
        qclass = self.__one
        question = qname + end + qtype + qclass
        self.query = id_ + conf_bits + qdcount + ancount + nscount + arcount + question
        self.questions.append(question)

    def send_query(self):
        udp_ip = "8.8.8.8"
        udp_port = 53
        conn = None
        data = bytes()
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            conn.connect((udp_ip, udp_port))
            conn.send(self.query)
            data = conn.recv(4096)
        except socket.error:
            print('Socket error')
        finally:
            conn.close()
        self.response_data = data
        self.io_response_data = io.BytesIO(data)
        self.questions_count = 1

    def _parse_response(self):
        self.header = self.response_data[:12]
        reply_code = bin(int.from_bytes(bytes([self.header[3]]), byteorder='big'))[6:]
        if reply_code == '0011':
            self.error = 'No such name (3)'
        self.answers_count, self.authority_count, self.additional_count = [int.from_bytes(x, byteorder='big')
                                                                           for x in [self.header[6:8],
                                                                                     self.header[8:10],
                                                                                     self.header[10:]]]

        ans_offset = len(self.header) + self.__get_section_length(self.questions)
        self.raw_answers = self.response_data[ans_offset:]
        prev = None
        for answer in self.__parse_answers():
            # Merge same answers (different ips)
            if prev and answer[0] == prev[0] and answer[1] == prev[1]:
                cur_entry = self.__create_entry(*answer)
                prev_entry = self.answers.pop()
                new_rdata = None
                if isinstance(prev_entry.data, list):
                    prev_entry.data.append(cur_entry.data)
                    new_rdata = prev_entry.data
                else:
                    new_rdata = [prev_entry.data, cur_entry.data]
                self.answers.append(DNSEntry(cur_entry.domain, cur_entry.type, cur_entry.class_, cur_entry.ttl,
                                             new_rdata))
            else:
                self.answers.append(self.__create_entry(*answer))
            prev = answer

    def __parse_answers(self):
        data = io.BytesIO(self.raw_answers)
        while data.tell() != len(self.raw_answers):
            name = self.__form_domain_name(self.__get_domain_name(io.BytesIO(), data, 0))
            type_ = data.read(2)
            class_ = data.read(2)
            ttl = data.read(4)
            rdlength = int.from_bytes(data.read(2), byteorder='big')
            rdata = data.read(rdlength)
            yield name, type_, class_, ttl, rdata

    def __get_section_length(self, param):
        return sum(map(len, param))

    def __get_domain_name(self, result, data, offset):
        if offset:
            data.seek(offset)

        while True:
            new_offset = self.__get_offset(data)
            if new_offset:
                self.__get_domain_name(result, self.io_response_data, new_offset)
                break
            else:
                d = data.read(1)
                if d == b'\x00':
                    break
                length = int.from_bytes(d, byteorder='big')
                result.write(d)
                result.write(data.read(length))
        return result

    def __get_offset(self, data):
        current_position = data.tell()
        first_byte = data.read(1)
        temp_bin = add_padding(bin(int.from_bytes(first_byte, byteorder='big')), '0b', 8)
        if temp_bin[2:].startswith('11'):
            offset = int(temp_bin[4:] + add_padding(bin(int.from_bytes(data.read(1), byteorder='big')), '0b', 8)[2:], 2)
            return offset
        data.seek(current_position)
        return None

    def __form_domain_name(self, data_io):
        data_io.seek(0)
        raw_data = data_io.read()
        data_io.seek(0)
        labels = []
        while data_io.tell() != len(raw_data):
            len_ = int.from_bytes(data_io.read(1), byteorder='big')
            labels.append(data_io.read(len_).decode('utf-8'))

        return '.'.join(labels)


def add_padding(s, prefix, padding):
    return prefix + s[2:].zfill(padding)


def main():
    host = 'localhost'
    port = 53
    DNSServer.raise_server(host, port, 4)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    while True:
        client.send('A dsadsadsad23423dsas.ru'.encode())
        d = client.recv(4096).decode(errors='ignore')
        print('!', d)
        time.sleep(2)

        client.send('SOA ru'.encode())
        d = client.recv(4096).decode(errors='ignore')
        print('!', d)
        time.sleep(2)

        client.send('A iana.org'.encode())
        d = client.recv(4096).decode(errors='ignore')
        print('!', d)
        time.sleep(2)

        client.send('MX mail.ru'.encode())
        d = client.recv(4096).decode(errors='ignore')
        print('!', d)
        time.sleep(2)
        break

    client.close()

if __name__ == '__main__':
    main()
