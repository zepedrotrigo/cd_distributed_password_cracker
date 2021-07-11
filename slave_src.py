import string, json, datetime, socket, base64, re, time, itertools, struct, selectors, math, random
from const import BANNED_TIME, MAX_TRIES, MIN_TRIES, MIN_VALIDATE, PASSWORD_SIZE, MAX_VALIDATE

MCAST_GRP = '224.1.1.1'
MCAST_PORT = 5007

class Slave:
    def __init__(self):
        self.sockp2p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sockp2p.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sockp2p.bind(('', MCAST_PORT))
        self.mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
        self.sockp2p.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, self.mreq)

        self.sockserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.sel = selectors.DefaultSelector()
        self.sel.register(self.sockp2p, selectors.EVENT_READ, self.read_p2p_msg) # UDP nao precisa de accept
        self.sel.register(self.sockserver, selectors.EVENT_READ, self.accept)

        self.slaveID = round(time.time() * 1000) # tempo em ms de inicio do processo
        self.slaves_info = {} # {slaveID : [last_comm_timestamp, last_guess, status]}
        self.max_slaves = 3
        self.guesses = []
        self.gen_passwords(PASSWORD_SIZE)
        self.comb_number = len(self.guesses)
        self.distribute = True
        self.guesses_copy = self.guesses
        self.uncertain = []
        self.pw_size = PASSWORD_SIZE
        self.request_time = None
        self.response_time = None
        self.tries = 0

        message = str({"method": "sincronize", "slave": self.slaveID, "last_guess":"", "known_slaves": list(self.slaves_info.keys())}).replace("'",'"')
        self.send_p2p_msg(message)

    def connect(self):
        self.sockserver.connect(('172.17.0.2', 8000))

    def accept(self, sock, mask): # este accept é so para a conexao com o sv
        conn, addr = sock.accept()
        conn.setblocking(False)
        self.sel.register(conn, selectors.EVENT_READ, self.receive_sv_msg)

    def read_p2p_msg(self, conn, mask):
        response = conn.recv(1024).decode("utf-8", "ignore")
        response = json.loads(response)

        if response["method"] == "sincronize":
            self.slaves_info[response["slave"]] = [time.time(),response["last_guess"], "online"] # {slaveID : [last_comm_timestamp, last_guess, status]}

            for slave in response["known_slaves"]:
                if slave not in self.slaves_info:
                    self.slaves_info[slave] = [math.inf, None, "online"]

                if time.time() - self.slaves_info[slave][0] > ((MAX_VALIDATE/1000)+0.1)*MAX_TRIES/1000+BANNED_TIME/1000: # o 0.1 é o timeout da socket
                    self.slaves_info[slave][2] = "offline" # tolerancia a falhas

        if response["method"] == "finalize":
            print("CORRECT PASSWORD:", response["correct_guess"])
            exit()

        if self.distribute and len(self.slaves_info) == 3:
            self.distribute_work(1)
            self.distribute_work(2)
            self.distribute_work(3)
            self.distribute = False

    def send_p2p_msg(self, message):
        self.sockp2p.sendto(bytes(message, encoding='utf-8'), (MCAST_GRP, MCAST_PORT))

    def request_auth(self, pw):
        str2bytes = f"root:{pw}".encode("ascii")
        base64_bytes = base64.b64encode(str2bytes)
        base64_string = base64_bytes.decode("ascii")

        data = f"GET / HTTP/1.1\nHost: 0.0.0.0:8000\nAuthorization: Basic {base64_string}\n\n"
        self.sockserver.send(bytes(data,"utf-8"))
        self.request_time = datetime.datetime.now()

    def receive_sv_msg(self):
        first_response = self.sockserver.recv(1024).decode("utf-8","ignore")
        self.response_time = datetime.datetime.now() - self.request_time
        self.response_time = self.response_time.total_seconds()

        if first_response.startswith("HTTP/1.1 200 OK"):
            return {'detail': 'OK'}

        elif first_response.endswith('{"detail":"Unauthorized"}'):
            return {"detail":"Unauthorized"}

        elif len(first_response) != 0:
            content_length = int(re.search('content-length: (.*)\n', first_response).group(1))
            content = self.sockserver.recv(content_length)

            if len(content) != 0:
                return json.loads(content.decode("utf-8"))

        return None

    def gen_passwords(self, n):
        for p in itertools.product(string.ascii_uppercase + string.ascii_lowercase + string.digits, repeat=n):
            self.guesses.append("".join(p))

    def check_ban(self):
        if self.response_time < MIN_VALIDATE/1000:
            return True

        return False

    def distribute_work(self, i):
        keys = self.slaves_info.keys()
        keys = sorted(keys)

        if self.slaveID == keys[i-1]:
            print(f"Distributing work for {self.slaveID} with number {i}")
            start = int(self.comb_number*((self.max_slaves-i)/self.max_slaves)) # 3-1 / 3
            end = int(self.comb_number*((self.max_slaves-i+1)/self.max_slaves)) # 3 / 3
            self.guesses = self.guesses[start:end]
            self.guesses_copy = self.guesses_copy[:start]+self.guesses_copy[end:] # nao preciso dos que eu vou fazer na copia
            if i != 1:
                self.uncertain.clear()

    def check_failures(self):        
        for slave in self.slaves_info: # tolerancia a falhas
            if self.slaves_info[slave][2] == "offline" and slave != self.slaveID:
                last_guess = self.slaves_info[slave][1]
                end = self.guesses_copy.index(last_guess)
                self.guesses = self.guesses_copy[:end]
                print("Guesses list updated to prevent failure point")
                break

    def loop(self):
        """Loop indefinetely.""" 
        response = {"detail" : "Unauthorized"}
        
        try:
            while response["detail"] != "OK":
                for key, mask in self.sel.select(0.1):
                    callback = key.data
                    callback(key.fileobj, mask)

                if len(self.guesses) != 0:
                    pw = self.guesses.pop()
                elif len(self.uncertain) != 0:
                    pw = self.uncertain.pop()
                else:
                    self.check_failures()

                    if len(self.guesses) != 0: # se nenhum esta offline e nao ha mais pws
                        pw = self.guesses.pop() # entao incrementa o tamanho da pw
                    else:
                        self.pw_size += 1
                        self.gen_passwords(self.pw_size)

                if self.tries < MIN_TRIES: # passwords que temos a certeza que testamos
                    self.request_auth(pw)
                    response = self.receive_sv_msg()
                    self.tries += 1
                else: 
                    self.uncertain.append(pw) # lista de pws para testar no fim (as que nao temos a certeza)
                    self.request_auth(pw)
                    response = self.receive_sv_msg()

                if self.check_ban():
                    message = str({"method": "sincronize", "slave": self.slaveID, "last_guess":pw, "known_slaves": list(self.slaves_info.keys())}).replace("'",'"')
                    self.send_p2p_msg(message)
                    
                    time.sleep(BANNED_TIME/1000)
                    self.tries = 0

                print(pw) #TODO debug remove
                
            print("CORRECT PASSWORD:", pw)
            message = str({"method": "finalize", "correct_guess": pw}).replace("'",'"')
            self.send_p2p_msg(message)

        except KeyboardInterrupt:
            self.sockp2p.close()
            self.sockserver.close()
