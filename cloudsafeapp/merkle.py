import hashlib
import pandas as pd

class Node:
    def __init__(self, data):
        self.data = data
        self.left = None
        self.right = None
        self.sibling_hashes = []

    def is_full(self):
        return self.left and self.right

    def __str__(self):
        return f"Data: {self.data}, Sibling Hashes: {self.sibling_hashes}"

    def is_leaf(self):
        return self.left is None and self.right is None

class MerkleTree:
    def __init__(self):
        self.root = None
        self._merkle_root = None
        self.sibling_hashes = []

    def __return_hash(self, x):
        return hashlib.sha256(x.encode('utf-8')).hexdigest()

    def make_tree_from_dataframe(self, data):
        if len(data) == 0:
            return None

        # Ensure the data is sorted in a consistent manner
        data = data.applymap(str).sort_values(by=data.columns.tolist()).reset_index(drop=True)
        
        # Convert each row to a consistent string representation
        hashed_data = [self.__return_hash(str(row)) for row in data.to_dict(orient='records')]
        self.root, _ = self._build_tree(hashed_data)
        self._calculate_merkle_root()

    def _build_tree(self, data):
        if len(data) == 1:
            return Node(data[0]), []  # Return node, empty sibling hash lists

        midpoint = len(data) // 2
        left_child, left_sibling_hashes = self._build_tree(data[:midpoint])
        right_child, right_sibling_hashes = self._build_tree(data[midpoint:])
        parent_hash = self.__return_hash(left_child.data + right_child.data)
        sibling_hashes = left_sibling_hashes + right_sibling_hashes

        parent_node = Node(parent_hash)
        parent_node.left = left_child
        parent_node.right = right_child

        left_child.sibling_hashes.append(right_child.data)
        right_child.sibling_hashes.append(left_child.data)

        self.sibling_hashes.append((left_child.data, right_child.data))

        return parent_node, sibling_hashes

    def _calculate_merkle_root(self):
        if not self.root:
            return

        def traverse(node):
            if node.is_leaf():
                return node.data
            left_hash = traverse(node.left)
            right_hash = traverse(node.right)
            return self.__return_hash(left_hash + right_hash)

        self._merkle_root = traverse(self.root)

    def get_merkle_root(self):
        return self._merkle_root

    def get_sibling_hashes(self):
        sibling_hashes = []
        
        def collect_sibling_hashes(node):
            if node is None or node.is_leaf():
                return
            if node.left and node.right:
                sibling_hashes.append((node.left.data, node.right.data))
            collect_sibling_hashes(node.left)
            collect_sibling_hashes(node.right)
        
        collect_sibling_hashes(self.root)
        return sibling_hashes
    
    def get_proofs(self, data):
        """
        Generates proofs for all data blocks in the tree.
        """
        if not self.root or not data:
            return None

        proofs = {}

        def traverse(node, current_index, proof=[]):
            if current_index >= len(data):
                return

            if current_index == node.data:  # Leaf node (data block)
                proofs[current_index] = proof.copy()  # Add proof to dictionary with index as key
                return

            midpoint = len(data) // 2
            if current_index < midpoint:
                sibling_index = midpoint + current_index
            else:
                sibling_index = current_index - midpoint
            if sibling_index < len(data):
                sibling_hash = node.sibling_hashes[midpoint - current_index - 1 if current_index < midpoint else current_index - midpoint]
                traverse(node.left, current_index, proof + [sibling_hash])
            traverse(node.right, current_index + midpoint, proof)  # Recursively traverse right child

        traverse(self.root, 0)
        return proofs
    

        