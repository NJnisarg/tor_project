import sys

sys.path.append('/home/praveenreddy/tor_project')
from node_directory_service.node_directory_service import NodeDirectoryService
from onion_router.router import OnionRouter

"""
    This file contains the main starting point of the onion router.
    This file will be run when the onion router is booted up
"""


# This function is the actual entry point that will be called
def main():
    node_num = sys.argv[1]
    print("Starting the onion router number:" + node_num)
    node = NodeDirectoryService.get_nodes_from_csv()[int(node_num)]
    onion_router = OnionRouter(node)
    while True:
        onion_router.listen()
        print("Started listening")
        onion_router.accept()
        print("Accepted")


main()
