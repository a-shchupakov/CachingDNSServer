import socket
import itertools
import io
import threading
import datetime
import pickle
import sys
import signal

from cache import CacheArray

ID = itertools.count()
SAVE_FILE = 'save.p'


def validate_cache_entry(entry):
    ttl, got_at = entry.ttl, entry.got_at
    expires_after = got_at + datetime.timedelta(seconds=ttl)
    today = datetime.datetime.today()
    return today < expires_after


class DNSServer:
    def __init__(self, main_server, host, port, validation_time):
        array = None
        try:
            array = pickle.load(open(SAVE_FILE, "rb"))
        except (EOFError, IOError):
            pass
        self.serialized = False
        self.host = host
        self.main_server = main_server
        self.port = port
        self.cache = CacheArray(validate_cache_entry, validation_time, back_up_array=array)
        self.cache_dispatcher = self.cache.dispatcher
        self.server = None
        self.is_alive = False

    def __serialize(self):
        print('Serializing cache...')
        self.cache_dispatcher.stop = True
        CacheArray.lock.acquire()
        with open(SAVE_FILE, 'wb') as f:
            CacheArray.lock.release()
            pickle.dump(self.cache.array, f)
        print('Done!')

    def raise_server(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind((self.host, self.port))
        threading.Thread(target=self._accept_conns, args=()).start()
        self.is_alive = True

    def shutdown(self):
        try:
            print("Shutting down server")
            self.server.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            pass
        finally:
            self.__serialize()
            self.server.close()
            self.is_alive = False

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
        print(query)
        answer = self._try_get_cache(query)
        print('------------------------------------')
        print('Cache: ', self.cache)
        print('------------------------------------')
        if answer:
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
        except Exception as e:
            return

    def _try_get_cache(self, query):
        io_question = io.BytesIO(query[12:])
        questions_count = int.from_bytes(query[4:6], byteorder='big')
        temp = DNSData()
        questions = []
        for i in range(0, questions_count):
            domain = temp._form_domain_name(temp._get_domain_name(io.BytesIO(), io_question, 0))
            type_ = io_question.read(2)
            _ = io_question.read(2)
            entries = self.cache[(type_, domain)]
            if entries:
                for entry in entries:
                    questions.append(entry)
            else:
                return None
        return questions

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
        ttl = int.from_bytes(ttl, byteorder='big')
        data = None
        if type_ == b'\x00\x01':
            data = rdata
        elif type_ in {b'\x00\x02', b'\x00\x03', b'\x00\x04'}:
            data = self._form_domain_name(self._get_domain_name(io.BytesIO(), io.BytesIO(rdata), 0))
        elif type_ == b'\x00\x0f':
            io_rdata = io.BytesIO(rdata)
            preference = io_rdata.read(2)
            name = self._form_domain_name(self._get_domain_name(io.BytesIO(), io_rdata, 0))
            data = preference, name
        elif type_ == b'\x00\x10':
            data = rdata
        elif type_ == b'\x00\x06':
            io_rdata = io.BytesIO(rdata)
            mname = self._form_domain_name(self._get_domain_name(io.BytesIO(), io_rdata, 0))
            rname = self._form_domain_name(self._get_domain_name(io.BytesIO(), io_rdata, 0))
            remains = io_rdata.read(20)
            data = mname, rname, remains
        else:
            return
        return DNSEntry(domain, type_, class_, ttl, data)

    def _create_response(self, source_query, answers):
        id_ = source_query[:2]
        questions_count = source_query[4:6]
        answers_count = len(answers).to_bytes(2, byteorder='big')
        auth_count, additional_count = b'\x00\x00', b'\x00\x00'
        temp_source_io = io.BytesIO(source_query[12:])
        questions = self._form_domain_name(self._get_domain_name(io.BytesIO(), temp_source_io, 0))
        questions += temp_source_io.read(4)
        remains_of_source_query = temp_source_io.read()  # Тут бывает посылаются Additional пакеты (в запросе). Их просто отбрасываем

        dns_response = (id_ + self.standard_response +
                        questions_count + answers_count + auth_count + additional_count +
                        questions)
        self.__create_pointers_from_question(questions, questions_count, source_query)

        actual_answers = 0
        for answer in answers:
            answer_bytes = self.__create_answer(answer, dns_response)
            if answer_bytes:
                actual_answers += 1
                dns_response += answer_bytes

        # Correct answer count value
        if actual_answers != len(answers):
            corrected_dns_response = dns_response[:6] + actual_answers.to_bytes(2, byteorder='big') + dns_response[8:]
            dns_response = corrected_dns_response

        return dns_response

    def __create_pointers_from_question(self, questions, questions_count, source_query):
        names = set()
        questions_io = io.BytesIO(questions)
        for i in range(0, int.from_bytes(questions_count, byteorder='big')):
            names.add(self._form_domain_name(self._get_domain_name(io.BytesIO(), questions_io, 0)))

        for name in names:
            self.__create_pointers_from_name(name, source_query)

    def __create_answer(self, entry, full_query):
        temp_full_query = full_query

        name = self.__encode_name(entry.domain, temp_full_query)
        type_ = entry.type
        class_ = entry.class_
        today = datetime.datetime.today()
        seconds_elapsed = (today - entry.got_at).seconds
        new_ttl = (entry.ttl - seconds_elapsed)
        if new_ttl <= 0:
            return b''
        ttl = new_ttl.to_bytes(4, byteorder='big')

        temp_full_query += name + type_ + class_ + ttl
        data = bytes()
        if entry.type == b'\x00\x01':
            data = entry.data
        elif entry.type in {b'\x00\x02', b'\x00\x03', b'\x00\x04'}:
            data = self.__encode_name(entry.data, temp_full_query)
        elif entry.type == b'\x00\x0f':
            data = entry.data[0] + self.__encode_name(entry.data[1], temp_full_query)
        elif entry.type == b'\x00\x10':
            data = entry.data
        elif entry.type == b'\x00\x06':
            data += self.__encode_name(entry.data[0], temp_full_query)
            data += self.__encode_name(entry.data[1], temp_full_query)
            data += entry.data[2]
        else:
            return b''
        length = len(data).to_bytes(2, byteorder='big')

        return name + type_ + class_ + ttl + length + data

    def __encode_name(self, raw_name, full_query):
        name = raw_name
        result = bytes()
        i = 0
        while True:
            if name in self.pointers:
                pointer = (int('0b1100000000000000', 2) + self.pointers[name]).to_bytes(2, byteorder='big')
                result += pointer
                break
            else:
                length = name[i]
                if length == b'\x00':
                    result += length
                    self.__create_pointers_from_name(raw_name, full_query)
                    break
                else:
                    if not isinstance(length, int):
                        length = int.from_bytes(length, byteorder='big')
                result += name[i:i + length + 1]
                name = name[i + length + 1:]
                i += length + 1
        return result

    def __create_pointers_from_name(self, name, source_query):
        if name == b'\x00':
            return
        pointer = source_query.find(name)
        if pointer != - 1 and name not in self.pointers:
            self.pointers[name] = pointer
        first_length = name[0]
        if first_length != b'\x00':
            self.__create_pointers_from_name(name[first_length + 1:], source_query)

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
        self.questions_count = int.from_bytes(data[4:6], byteorder='big')

    def __parse_questions(self, query, questions_count):
        io_query = io.BytesIO(query)
        for i in range(0, questions_count):
            name = self._get_domain_name(io.BytesIO(), io_query, 0)
            name.seek(0)
            type_ = io_query.read(2)
            class_ = io_query.read(2)
            self.questions.append(name.read() + type_ + class_)

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
        for answer in self.__parse_answers():
            entry = self.__create_entry(*answer)
            if entry:
                self.answers.append(entry)

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
                    result.write(d)
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
        return raw_data  # Нет смысла переводить байты в доменное имя
        # data_io.seek(0)
        # labels = []
        # while data_io.tell() != len(raw_data):
        #     len_ = int.from_bytes(data_io.read(1), byteorder='big')
        #     labels.append(data_io.read(len_).decode('utf-8'))
        #
        # return '.'.join(labels)


def add_padding(s, prefix, padding):
    return prefix + s[2:].zfill(padding)


def main():
    def shutdown_server(sig, unused):
        """
        Shutsdown server from a SIGINT received signal
        """
        server.shutdown()
        sys.exit(1)

    host = 'localhost'
    port = 53
    main_server = None
    try:
        main_server = sys.argv[1]
    except IndexError:
        main_server = '8.8.8.8'
        print('Main DNS server is now ' + main_server)

    if main_server:
        signal.signal(signal.SIGINT, shutdown_server)
        server = DNSServer(main_server, host, port, 4)
        server.raise_server()
        print("Press Ctrl+C to shut down server.")
        while True:
            pass


if __name__ == '__main__':
    main()
