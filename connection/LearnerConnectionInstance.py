import socket

from events.Events import SendInitialCHLOEvent, SendGETRequestEvent, CloseConnectionEvent, SendFullCHLOEvent


class LearnerConnectionInstance:
    """
    Instance that communicates with the learner and instructs the sender to send specific messages to the QUIC server.
    This is the server
    """

    __observers = []
    __socket = None
    __connection = None
    __running = True

    def set_up_communication_server(self):
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host = '192.168.43.40'
        port = 4142
        ip = socket.gethostbyname(host)
        self.__socket.bind((host, port))
        print("Connected to host {} ({}) and port {}".format(host, ip, port))
        self.__socket.listen()
        while True:
            try:
                self.__connection, addr = self.__socket.accept()
                print("Accepted incoming connection from {}".format(addr))
                while self.__running:
                    data = self.__connection.recv(20)
                    if data:
                        print("Received data from connection {}".format(data))
                        self.__parse_data(data)
            except KeyboardInterrupt:
                if self.__connection:
                    self.__socket.close()
                    self.__connection.close()   # Ensure single instance.
                break

    def respond(self, response):
        print("Sending response {}".format(response))
        self.__connection.send(response)

    def __parse_data(self, data):
        data = data.decode('UTF-8').rstrip()
        if data == "INIT-CHLO":
            print("Performing Inchoate CHLO")
            self.update(SendInitialCHLOEvent())
        elif data == "GET":
            print("Performing GET Request")
            self.update(SendGETRequestEvent())
        elif data == "CLOSE":
            print("Performing Close Event")
            self.update(CloseConnectionEvent())
        elif data == "FULL-CHLO":
            print("Performing Full CHLO")
            self.update(SendFullCHLOEvent())
        else:
            print("Unknown received command. {} ".format(data))

    def add_observer(self, observer):
        self.__observers.append(observer)

    def update(self, event):
        for observer in self.__observers:
            observer.update(event)
