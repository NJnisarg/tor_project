import connection.Skt

class Circuit:

    def __init__(self, skt:Skt, num_hops=3):
        self.num_hops = num_hops
        self.own_Skt = skt