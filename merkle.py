import hashlib
import datetime

class Node:
    def __init__(self, left, right, value, content, is_copied = False):
        self.left: Node = left
        self.right: Node = right
        self.value = value
        self.content = content
        self.is_copied = is_copied

    def hash(val):
        return hashlib.sha256(val.encode("utf-8")).hexdigest()

    def __str__(self):
        return str(self.value)

    def copy(self):
        return Node(self.left, self.right, self.value, self.content, True)


class MerkleTree:
    def __init__(self, values):
        self.__buildTree(values)

    def __buildTree(self, values):
        leaves = [Node(None, None, Node.hash(str(e)), str(e)) for e in values]
        if len(leaves) % 2 == 1:
            leaves.append(leaves[-1].copy())
        self.root: Node = self.__buildTreeRec(leaves)

    def __buildTreeRec(self, nodes) -> Node:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1].copy())
        half = len(nodes) // 2

        if len(nodes) == 2:
            return Node(nodes[0], nodes[1],
                        Node.hash(nodes[0].value + nodes[1].value),
                        nodes[0].content + "+" + nodes[1].content)

        left: Node = self.__buildTreeRec(nodes[:half])
        right: Node = self.__buildTreeRec(nodes[half:])
        value = Node.hash(left.value + right.value)
        content = f"{left.content}+{right.content}"
        return Node(left, right, value, content)

    def printTree(self):
        self.__printTreeRec(self.root)

    def __printTreeRec(self, node: Node):
        if node is not None:
            if node.left is not None:
                print("Left: " + str(node.left))
                print("Right: " + str(node.right))
            else:
                print("Input")
            if node.is_copied:
                print("(Padding)")
            print("Value: " + str(node.value))
            print("Content: " + str(node.content))
            print("")
            self.__printTreeRec(node.left)
            self.__printTreeRec(node.right)

    def getRootHash(self):
        return self.root.value

    def getAuthenticationPath(self, leaf_index):
        leaves = []

        def collect_leaves(node: Node):
            if node.left is None and node.right is None:
                leaves.append(node)
            else:
                collect_leaves(node.left)
                collect_leaves(node.right)

        collect_leaves(self.root)
        if leaf_index < 0 or leaf_index >= len(leaves):
            raise IndexError("leaf_index out of range for authentication path")

        path = {}
        def find_and_collect(node: Node, depth, target_node: Node):
            if node is None:
                return False
            if node is target_node:
                return True
            if node.left and find_and_collect(node.left, depth + 1, target_node):
                # sibling is on the right
                path[f"{depth}r"] = node.right.value
                return True
            if node.right and find_and_collect(node.right, depth + 1, target_node):
                # sibling is on the left
                path[f"{depth}l"] = node.left.value
                return True
            return False

        target_leaf = leaves[leaf_index]
        # start depth at 0 for leaf level (consistent with previous code style)
        find_and_collect(self.root, 0, target_leaf)
        path[f"{len(path)}z"] = self.root.value
        return path


def mixmerkletree(values):
    mtree = MerkleTree(values)
    print("Root Hash: " + mtree.getRootHash() + "\n")
    return mtree.getRootHash(), mtree


def Ver_merkle_path(auth_path, root_hash):
    entries = [(int(k[:-1]), k[-1], v) for k, v in auth_path.items() if not k.endswith("z")]
    # sort by depth ascending to follow bottom-to-top order
    entries.sort(key=lambda x: x[0])

    prev_hash = None
    i = 0
    while i < len(entries):
        depth = entries[i][0]
        # collect all entries with this depth
        same_depth = []
        while i < len(entries) and entries[i][0] == depth:
            same_depth.append(entries[i])
            i += 1

        # if no previous hash (we're at leaf level)
        if prev_hash is None:
            if len(same_depth) == 2:
                # expect one 'l' and one 'r'
                left = next((h for (d, lr, h) in same_depth if lr == "l"), None)
                right = next((h for (d, lr, h) in same_depth if lr == "r"), None)
                if left is None or right is None:
                    # malformed path
                    return False
                prev_hash = hashlib.sha256(left.encode("utf-8") + right.encode("utf-8")).hexdigest()
            elif len(same_depth) == 1:
                # only one sibling present at leaf level: treat sibling as left or right
                lr = same_depth[0][1]
                sibling_hash = same_depth[0][2]
                # Without explicit leaf value we cannot compute; return False (malformed)
                return False
            else:
                return False
        else:
            # combine the prev_hash with the single sibling at this depth
            if len(same_depth) != 1:
                # unexpected: after bottom level we should have exactly one sibling per level
                # if there are two, try to reduce them first (unlikely with this generator)
                left = next((h for (d, lr, h) in same_depth if lr == "l"), None)
                right = next((h for (d, lr, h) in same_depth if lr == "r"), None)
                if left and right:
                    combined = hashlib.sha256(left.encode("utf-8").encode("utf-8") if False else b'').hexdigest()  # unreachable; kept safe
                return False
            lr = same_depth[0][1]
            sibling_hash = same_depth[0][2]
            if lr == "l":
                prev_hash = hashlib.sha256(sibling_hash.encode("utf-8") + prev_hash.encode("utf-8")).hexdigest()
            else:
                prev_hash = hashlib.sha256(prev_hash.encode("utf-8") + sibling_hash.encode("utf-8")).hexdigest()

    # final check
    if prev_hash is None:
        return False
    return prev_hash == root_hash


def printPoly(poly, n):
    polynomial_str = ""
    for i in range(n):
        if poly[i] != 0:
            polynomial_str += str(poly[i]) + "x^" + str(i) + " + "
    polynomial_str = polynomial_str[:-3] if polynomial_str else ""
    print(polynomial_str)


def evaluate_polynomial(coefficients, x):
    result = 0
    for i, coef in enumerate(coefficients):
        result += coef * (x ** (len(coefficients) - 1 - i))
    return result


def listToString(s):
    if not s:
        return ""
    return ",".join(str(ele) for ele in s)


def get_timestamp() -> float:
    return datetime.datetime.now().timestamp()
