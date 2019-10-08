# An Implementation of the Tor Protocol

This project deals with the understanding and implementation of The Onion Routing Protocol.

# Code organization

- The code is organized into modules. These modules are based on the spec of the tor project.
- The project starts with a base implementation with bare minimum modules to operate.
- Currently there are the following 3 higher level modules:
    - cell: Describing the Tor Cell(message) for communication between the nodes
    - onion_proxy: The client side of the Tor.
    - onion_router: The user process that will run on a tor node that wants to participate in the circuit.
- More modules will be added and the above organization of the code is subject to refactoring based on the progress of the project.

# Coding conventions

- The project roughly follows the PEP8 style guide. [PEP8 Guide](https://www.python.org/dev/peps/pep-0008/)
- Every package/module will follow `snake_case` convention.
- The class names are in `PascalCase`.
- The functions and variables must be in `snake_case`.