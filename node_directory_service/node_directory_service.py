import csv
from typing import List
from connection.node import Node
from crypto.core_crypto import CoreCryptoRSA
from config.env_config import BASE_PROJECT_DIR


class NodeDirectoryService:

	@staticmethod
	def get_rand_three_nodes() -> List[Node]:
		"""
		Method returns 3 nodes for circuit building
		This method simply uses the csv file. We will later replace that with an actual http server instance that serves this list.
		:return: A List of 3 Node objects
		"""

		return NodeDirectoryService.get_nodes_from_csv()

	@staticmethod
	def get_nodes_from_csv() -> List[Node]:
		"""
		Reads the predetermined CSV and then returns the list of nodes including the client node itself
		:return: A list of nodes, including the client node itself
		"""
		node_container = []
		try:
			with open(BASE_PROJECT_DIR+'/node_directory_service'+'/tor_nodes_list.csv') as f:
				data = csv.reader(f)
				for i, row in enumerate(data):
					id_pub = CoreCryptoRSA.load_public_key_from_disc(
						BASE_PROJECT_DIR + '/node_directory_service' + '/keyfiles' + '/' + row[2]+'.pub')

					onion_pub = CoreCryptoRSA.load_public_key_from_disc(
						BASE_PROJECT_DIR + '/node_directory_service' + '/keyfiles' + '/' + row[3]+'.pub')

					node = Node(row[0], int(row[1]), None, id_pub, None, onion_pub)

					# Only for the client node we load its private keys. Other nodes we can't
					if i == 0:
						id_priv = CoreCryptoRSA.load_private_key_from_disc(
							BASE_PROJECT_DIR + '/node_directory_service' + '/keyfiles' + '/' + row[2])
						node.identity_key_pri = id_priv

						onion_priv = CoreCryptoRSA.load_private_key_from_disc(
							BASE_PROJECT_DIR + '/node_directory_service' + '/keyfiles' + '/' + row[3])
						node.onion_key_pri = onion_priv

					node_container.append(node)

			return node_container
		except:
			print("Trying to read from CSV. Something went wrong!")
			return list()
