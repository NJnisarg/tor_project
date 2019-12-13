import sys
sys.path.append('/home/njnisarg/tor_project')
from node_directory_service.node_directory_service import NodeDirectoryService
from router.onion_router import OnionRouter

"""
    This file contains the main starting point of the onion router.
    This file will be run when the onion router is booted up
"""


# This function is the actual entry point that will be called
def main():
	print("Starting the onion router")
	node = NodeDirectoryService.get_nodes_from_csv()[0]
	onion_router = OnionRouter(node)
	while True:
		onion_router.listen()
		print("Started listening")
		onion_router.accept()
		print("Accepted")

main()
