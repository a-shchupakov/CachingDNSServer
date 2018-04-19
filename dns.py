import socket
import itertools
import binascii
import io
import threading
import datetime
import pickle
import sys
import signal

from cache import CacheDict

ID = itertools.count()
SAVE_FILE = 'save.p'


def validate_cache_entry(entry):
    ttl, got_at = entry.ttl, entry.got_at
    expires_after = got_at + datetime.timedelta(seconds=ttl)
    today = datetime.datetime.today()
    return today < expires_after


class DNSServer:
    def __init__(self, main_server, host, port, validation_time):
        dict_ = None
        try:
            dict_ = pickle.load(open(SAVE_FILE, "rb"))
        except (EOFError, IOError):
            pass
        self.serialized = False
        self.host = host
        self.main_server = main_server
        self.port = port
        self.cache = CacheDict(validate_cache_entry, validation_time, back_up_dict=dict_)
        self.cache_dispatcher = self.cache.dispatcher
        self.server = None

    def __serialize(self):
        print('Serializing cache...')
        self.cache_dispatcher.stop = True
        CacheDict.lock.acquire()
        with open(SAVE_FILE, 'wb') as f:
            CacheDict.lock.release()
            pickle.dump(self.cache.dict, f)
        print('Done!')

    def raise_server(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind((self.host, self.port))
        threading.Thread(target=self._accept_conns, args=()).start()

    def shutdown(self):
        try:
            print("Shutting down server")
            self.server.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            pass
        finally:
            self.__serialize()
            self.server.close()

    def _accept_conns(self):
        print('Waiting for connections on {} {}'.format(self.host, self.port))
        while True:
            try:
                data, addr = self.server.recvfrom(1024)
                print(addr)
                threading.Thread(target=self._handle_query, args=(data, addr)).start()
            except Exception as e:
                break

    def _handle_query(self, query, client):
        print('Client connected on {}'.format(client))
        answer = self._try_get_cache(query)
        print('------------------------------------')
        print('Cache: ', self.cache.dict)
        print('------------------------------------')
        if answer:  # TODO: del it
            try:
                response = DNSData()._create_response(query, answer)
                self.server.sendto(response, client)
            except ValueError:
                pass
            else:
                print('Cache hit!')
                return
        print('Cache miss :(')
        try:
            dns_data = DNSData()
            answers = dns_data.process_name(query, self.main_server)
            self.update_cache(answers)
            self.server.sendto(dns_data.response_data, client)
        except:
            return

    def _try_get_cache(self, query):
        io_question = io.BytesIO(query[12:])
        temp = DNSData()
        domain = temp._form_domain_name(temp._get_domain_name(io.BytesIO(), io_question, 0))
        type_ = temp.types[int.from_bytes(io_question.read(2), byteorder='big')]
        return self.cache[(type_, domain)]

    def update_cache(self, answers):
        for answer in answers:
            self.cache[(answer.type, answer.domain)] = answer


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
        self.pointers = dict()
        self.error = None
        self.standard_response = b'\x81\x80'
        self.types = {1: 'A', 2: 'NS', 3: 'MD', 15: 'MX', 4: 'MF', 16: 'TXT', 6: 'SOA'}
        self.byte_qtypes = {'A': self.__one, 'NS': bytes.fromhex('0002'),
                            'MD': bytes.fromhex('0003'), 'SOA': bytes.fromhex('0006'),
                            'MX': bytes.fromhex('000F'), 'MF': bytes.fromhex('0004'),
                            'TXT': bytes.fromhex('0010')}
        self.answers = []

    def process_name(self, query, ip):
        self.query = query
        self.send_query(ip)
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
            data = rdata
        elif qtype in {'NS', 'MD', 'MF'}:
            data = self._form_domain_name(self._get_domain_name(io.BytesIO(), io.BytesIO(rdata), 0))
        elif qtype == 'MX':
            io_rdata = io.BytesIO(rdata)
            preference = int.from_bytes(io_rdata.read(2), byteorder='big')
            name = self._form_domain_name(self._get_domain_name(io.BytesIO(), io_rdata, 0))
            data = preference, name
        elif qtype == 'TXT':
            data = rdata.decode('utf-8', errors='ignore')
        elif qtype == 'SOA':
            io_rdata = io.BytesIO(rdata)
            mname = self._form_domain_name(self._get_domain_name(io.BytesIO(), io_rdata, 0))
            rname = self._form_domain_name(self._get_domain_name(io.BytesIO(), io_rdata, 0))
            serial, refresh, retry, expire, minimum = [int.from_bytes(x, byteorder='big') for x in
                                                       [io_rdata.read(4),
                                                        io_rdata.read(4),
                                                        io_rdata.read(4),
                                                        io_rdata.read(4),
                                                        io_rdata.read(4)]]
            data = mname, rname, serial, refresh, retry, expire, minimum

        return DNSEntry(domain, qtype, class_, ttl, data)

    def _create_response(self, source_query, entry):
        answer = bytes()
        answer = source_query[:2] + self.standard_response + source_query[4:6]
        count = len(entry.data) if isinstance(entry.data, list) else 1
        answer += count.to_bytes(2, byteorder='big')
        answer += source_query[8:]
        self.__create_pointers(source_query[12:], source_query)
        answer += self.__create_answer(entry, count != 1)
        return answer

    def __create_answer(self, entry, is_list=False):
        if not is_list:
            entry.data = [entry.data]
        result = bytes()
        for entry_data in entry.data:
            result += self.__encode_name(entry.domain)
            result += self.byte_qtypes[entry.type]
            result += self.__one
            today = datetime.datetime.today()
            seconds_elapsed = (today - entry.got_at).seconds
            new_ttl = (entry.ttl - seconds_elapsed)
            if new_ttl <= 0:
                raise ValueError()
            result += new_ttl.to_bytes(4, byteorder='big')
            data = bytes()
            if entry.type == 'A':
                data = entry_data
            elif entry.type in {'NS', 'MD', 'MF'}:
                data = self.__encode_name(entry_data)
            elif entry.type == 'MX':
                data = entry_data[0].to_bytes(2, byteorder='big') + self.__encode_name(entry_data[1])
            elif entry.type == 'TXT':
                data = entry_data.encode('utf-8')
            elif entry.type == 'SOA':
                data += self.__encode_name(data[0])
                data += self.__encode_name(data[1])
                data += b''.join([x.to_bytes(4, byteorder='big') for x in entry_data[2:]])
            result += len(data).to_bytes(2, byteorder='big') + data
        return result

    def __encode_name(self, raw_name):
        name = b''.join([bytes([len(x)]) + x.encode('utf-8') for x in raw_name.split('.')])
        result = bytes()
        i = 0
        while name != b'\x00':
            if name in self.pointers:
                pointer = (int('0b1100000000000000', 2) + self.pointers[name]).to_bytes(2, byteorder='big')
                result += pointer
                break
            else:
                length = int.from_bytes(name[i], byteorder='big')
                result += name[i:i + length + 1]
                i += length + 1
        return result

    def __create_pointers(self, data, source_query):
        result = io.BytesIO()
        io_data = io.BytesIO(data)
        first_length = 0
        while True:
            new_offset = self.__get_offset(io_data)
            if new_offset:
                return
            d = io_data.read(1)
            if d == b'\x00':
                break
            length = int.from_bytes(d, byteorder='big')
            if not first_length:
                first_length = length
            result.write(d)
            result.write(io_data.read(length))
        result.seek(0)
        domain_name = result.read()

        pointer = source_query.find(domain_name)
        self.pointers[domain_name] = pointer

        if first_length:
            self.__create_pointers(data[first_length + 1:], source_query)


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

    def send_query(self, ip):
        port = 53
        conn = None
        data = bytes()
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            conn.connect((ip, port))
            conn.send(self.query)
            data = conn.recv(4096)
        except socket.error:
            print('Socket error')
        finally:
            conn.close()
        self.response_data = data
        self.io_response_data = io.BytesIO(data)
        self.questions_count = 1

    def __parse_questions(self, query, questions_count):
        io_query = io.BytesIO(query)
        for i in range(0, questions_count):
            name = self._get_domain_name(io.BytesIO(), io_query, 0)
            name.seek(0)
            end = self.__end
            type_ = io_query.read(2)
            class_ = io_query.read(2)
            self.questions.append(name.read() + end + type_ + class_)

    def _parse_response(self):
        self.header = self.response_data[:12]
        self.answers_count, self.authority_count, self.additional_count = [int.from_bytes(x, byteorder='big')
                                                                           for x in [self.header[6:8],
                                                                                     self.header[8:10],
                                                                                     self.header[10:]]]
        try:
            self.__parse_questions(self.query[12:], self.questions_count)
        except Exception as e:
            pass
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
            name = self._form_domain_name(self._get_domain_name(io.BytesIO(), data, 0))
            type_ = data.read(2)
            class_ = data.read(2)
            ttl = data.read(4)
            rdlength = int.from_bytes(data.read(2), byteorder='big')
            rdata = data.read(rdlength)
            yield name, type_, class_, ttl, rdata

    def __get_section_length(self, param):
        return sum(map(len, param))

    def _get_domain_name(self, result, data, offset):
        if offset:
            data.seek(offset)

        while True:
            new_offset = self.__get_offset(data)
            if new_offset:
                self._get_domain_name(result, self.io_response_data, new_offset)
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

    def _form_domain_name(self, data_io):
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
    def shutdown_server(sig, unused):
        """
        Shutsdown server from a SIGINT recieved signal
        """
        server.shutdown()
        sys.exit(1)

    host = 'localhost'
    port = 53
    main_server = None
    try:
        main_server = sys.argv[1]
    except IndexError:
        print('Select main DNS server')

    if main_server:
        signal.signal(signal.SIGINT, shutdown_server)
        server = DNSServer(main_server, host, port, 4)
        server.raise_server()
        print("Press Ctrl+C to shut down server.")
        while True:
            pass


if __name__ == '__main__':
    main()
