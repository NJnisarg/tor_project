

"""
    This file contains the main starting point of the onion proxy.
    This file will be run when the onion proxy is booted up
"""

# This function is the actual entry point that will be called
def main():
    print("Onion proxy started!")

    print("Setting up a circuit")

    # socket = create_initial_socket()
    # circuit = None
    # if socket is not None:
    #     circuit = setup_initial_circuit()
    #     if circuit is not None:
    #         print("Circuit successfully setup!")
    #     else:
    #         print("Failure in setting up the circuit! Exiting the onion proxy")
    #         exit
    # else:
    #     print("Failure in setting up the socket")
    #     exit