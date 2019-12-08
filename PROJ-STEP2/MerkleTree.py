class Node(object):
    def __init__(self, data):
        self.data = data

class MerkleError(Exception):
    pass

class MerkleTree(object):
    def __init__(self, leaves, hashFunc):
        self.hashFunc = hashFunc
        self.leaves = [Node(self.hashFunc(leaf)) for leaf in leaves]
        self.root = None

    def build(self):
        if not self.leaves:
            raise MerkleError('The tree has no leaves and cannot be calculated.')

        # Moving buttom up, layer by layer
        layer = self.leaves[::]
        while len(layer) != 1:
            layer = self._build(layer)

        self.root = layer[0]
        return self.root.data

    def _build(self, leaves):
        layer, odd = [], None

        # check if even number of leaves, promote odd leaf to next level, if not
        if len(leaves) % 2 == 1:
            odd = leaves.pop(-1)
        for i in range(0, len(leaves), 2):
            parent = Node(self.hashFunc(leaves[i].data + leaves[i + 1].data))
            layer.append(parent)
        if odd:
            layer.append(odd)
            
        return layer
