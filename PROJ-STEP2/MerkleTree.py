class Node(object):
    def __init__(self, data):
        self.data = data

class MerkleError(Exception):
    pass

class MerkleTree(object):
    def __init__(self, leaves, hashFunc):
        self.hashFunc = hashFunc
        # take hashes of each leave
        self.leaves = [Node(self.hashFunc(bytearray( leaf , 'UTF-8'))) for leaf in leaves]
        self.root = None

    def build(self):
        if not self.leaves:
            raise MerkleError('The tree has no leaves.')
        elif len(self.leaves) != 1 and len(self.leaves) % 2 == 1:
            raise MerkleError('The tree has odd number of leaves')

        # Moving buttom up, layer by layer
        layer = self.leaves[::]
        while len(layer) != 1:
            layer = self._build(layer)

        self.root = layer[0]
        return self.root.data

    def _build(self, leaves):
        layer = []

        for i in range(0, len(leaves), 2):
            parent = Node(self.hashFunc(b"".join( [ leaves[i].data , leaves[i + 1].data ] )))
            layer.append(parent)
           
        return layer
