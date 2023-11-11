#!/usr/bin/env python

import os
import os.path
import sys
import time
import logging

from pylstar.LSTAR import LSTAR
from pylstar.ActiveKnowledgeBase import ActiveKnowledgeBase
from pylstar.Letter import Letter
from pylstar.Word import Word
from pylstar.eqtests import RandomWalkMethod


from ServerKnowledgeBase import QUICServerKnowledgeBase




def log_fn(log_file, s):
    print(s, end="")
    sys.stdout.flush()
    log_file.write(s)


def main():

    input_vocabulary = [
        "InitialCHLO",
        "FullCHLO",
        # "ZERO-RTT",
        # "SendGETRequestEvent", 
        # "CloseConnectionEvent", 
        # "SendFullCHLOEvent", 
        # "ZeroRTTCHLOEvent", 
        # "ResetEvent"
    ]


    quicServerBase = QUICServerKnowledgeBase("127.0.0.1", 443)
    try:
        # eqtest = RandomWalkMethod(quicServerBase, input_vocabulary, 10000, 0.7)
        lstar = LSTAR(input_vocabulary, quicServerBase, max_states = 2)
        quicServer_state_machine = lstar.learn()
    except:
        print("Some Error Occured")
        exit()
        
    dot_code = quicServer_state_machine.build_dot_code()

    output_file = "quic_server_infer_litespeed.dot"

    with open(output_file, "w") as fd:
        fd.write(dot_code)

    print("==> QUIC machine Automata dumped in {}".format(output_file))
    print("Knowledge base stats: {}".format(quicServerBase.stats))


if __name__ == "__main__":
    main()