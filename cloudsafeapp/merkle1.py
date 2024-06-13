import hashlib
import pandas as pd

# Node class that represents a node of a binary tree
class Node:
    def __init__(self, data):
        self.data = data
        self.left = None
        self.right = None

    def isFull(self):
        return self.left and self.right

    def __str__(self):
        return self.data

    def isLeaf(self):
        return (self.left == None) and (self.right == None)

# Merkle tree class for actual implementation of the tree
class MerkleTree:
    def __init__(self):
        self.root = None
        self._merkleRoot = ''

    def __returnHash(self, x):
        return hashlib.sha256(x.encode()).hexdigest()

    def makeTreeFromDataFrame(self, df):
        def __noOfNodesReqd(df):
            x = len(df)
            return 2 * x - 1

        def __buildTree(arr, root, i, n):
            if i < n:
                temp = Node(str(arr[i]))
                root = temp
                root.left = __buildTree(arr, root.left, 2 * i + 1, n)
                root.right = __buildTree(arr, root.right, 2 * i + 2, n)
            return root

        def __addLeafData(df, node):
            if not node:
                return
            __addLeafData(df, node.left)
            if node.isLeaf():
                node.data = self.__returnHash(''.join(''.join(map(str, row)) for _, row in df.iterrows()))
            else:
                node.data = ''
            __addLeafData(df, node.right)

        nodesReqd = __noOfNodesReqd(df)
        nodeArr = [num for num in range(1, nodesReqd + 1)]
        self.root = __buildTree(nodeArr, self.root, 0, nodesReqd)
        __addLeafData(df.copy(), self.root)

    def inorderTraversal(self, node):
        if not node:
            return
        self.inorderTraversal(node.left)
        print(node)
        self.inorderTraversal(node.right)

    def calculateMerkleRoot(self):
        def __merkleHash(node):
            if node.isLeaf():
                return node
            left = __merkleHash(node.left).data
            right = __merkleHash(node.right).data
            node.data = self.__returnHash(left + right)
            return node

        merkleRoot = __merkleHash(self.root)
        self._merkleRoot = merkleRoot.data
        return self._merkleRoot

    def getMerkleRoot(self):
        return self._merkleRoot

    def verifyUtil(self, df):
        hash1 = self.getMerkleRoot()
        new_tree = MerkleTree()
        new_tree.makeTreeFromDataFrame(df)
        new_tree.calculateMerkleRoot()
        hash2 = new_tree.getMerkleRoot()
        if hash1 == hash2:
            print("Transactions verified Successfully")
            return True
        else:
            print("Transactions have been tampered")
            return False

# Example usage
data = {'transactions': ['txn1', 'txn2', 'txn3', 'txn4'],'index':[1,2,3,4]}
df = pd.DataFrame(data)

merkle_tree = MerkleTree()
merkle_tree.makeTreeFromDataFrame(df)
merkle_tree.calculateMerkleRoot()

print("Merkle Root:", merkle_tree.getMerkleRoot())

# Verification example
data_verification = {'transactions': ['txn1', 'txn2', 'txn3', 'txn4'],'index':[1,5,3,4]}
df_verification = pd.DataFrame(data_verification)
merkle_tree.verifyUtil(df_verification)


#b70d97143ee7caaae5a6fd343a5a26abc3b443ef4be573c8e9cec24cd86356d2
#451d6e46deae86004dffa1d109ac972fabff4e7e394f33f8e62c4414077478b8