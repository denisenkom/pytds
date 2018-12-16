class MockSock(object):
    def __init__(self, input_packets=()):
        self.set_input(input_packets)
        self._out_packets = []
        self._closed = False

    def recv(self, size):
        if not self.is_open():
            raise Exception('Connection closed')
        if self._curr_packet >= len(self._packets):
            return b''
        if self._packet_pos >= len(self._packets[self._curr_packet]):
            self._curr_packet += 1
            self._packet_pos = 0
        if self._curr_packet >= len(self._packets):
            return b''
        res = self._packets[self._curr_packet][self._packet_pos:self._packet_pos+size]
        self._packet_pos += len(res)
        return res

    def recv_into(self, buffer, size=0):
        if not self.is_open():
            raise Exception('Connection closed')
        if size == 0:
            size = len(buffer)
        res = self.recv(size)
        buffer[0:len(res)] = res
        return len(res)

    def send(self, buf, flags=0):
        if not self.is_open():
            raise Exception('Connection closed')
        self._out_packets.append(buf)
        return len(buf)

    def sendall(self, buf, flags=0):
        if not self.is_open():
            raise Exception('Connection closed')
        self._out_packets.append(buf)

    def setsockopt(self, *args):
        pass

    def close(self):
        self._closed = True

    def is_open(self):
        return not self._closed

    def consume_output(self):
        """
        Retrieve data from output queue and then clear output queue
        @return: bytes
        """
        res = self._out_packets
        self._out_packets = []
        return b''.join(res)

    def set_input(self, packets):
        """
        Resets input queue
        @param packets: List of input packets
        """
        self._packets = packets
        self._curr_packet = 0
        self._packet_pos = 0
