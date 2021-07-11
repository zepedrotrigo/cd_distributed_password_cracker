from slave_src import Slave
from const import PASSWORD_SIZE

if __name__ == "__main__": # neste ficheiro colocar 3 threads com pw_sizes iniciais diferentes, se a pw for dinamica
    s = Slave()
    s.connect()
    s.loop()