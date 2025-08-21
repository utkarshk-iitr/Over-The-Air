import hashlib
import datetime

class Node: 
    def __init__(self, left, right, value, content, is_copied=False):
        self.left = left
        self.right = right
        self.value = value
        self.content = content
        self.is_copied = is_copied
         
    @staticmethod
    def hash(val) -> str:
        return hashlib.sha256(val.encode('utf-8')).hexdigest()
 
    def __str__(self):
        return (str(self.value))
 
    def copy(self):
        return Node(self.left, self.right, self.value, self.content, True)
       
class MerkleTree:
    def __init__(self, values):
        self.__buildTree(values)
 
    def __buildTree(self, values):
 
        leaves = [Node(None, None, Node.hash(str(e)), str(e)) for e in values]
        if len(leaves) % 2 == 1:
            leaves.append(leaves[-1].copy())
        self.root = self.__buildTreeRec(leaves)
 
    def __buildTreeRec(self, nodes) -> Node:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1].copy())
        half = len(nodes) // 2
 
        if len(nodes) == 2:
            return Node(nodes[0], nodes[1], Node.hash(nodes[0].value + nodes[1].value), nodes[0].content+"+"+nodes[1].content)
 
        left = self.__buildTreeRec(nodes[:half])
        right = self.__buildTreeRec(nodes[half:])
        value = Node.hash(left.value + right.value)
        content = f'{left.content}+{right.content}'
        return Node(left, right, value, content)
 
    def printTree(self):
        self.__printTreeRec(self.root)
         
    def __printTreeRec(self, node):
        if node != None:
            if node.left != None:
                print("Left: "+str(node.left))
                print("Right: "+str(node.right))
            else:
                print("Input")
                 
            if node.is_copied:
                print('(Padding)')
            print("Value: "+str(node.value))
            print("Content: "+str(node.content))
            print("")
            self.__printTreeRec(node.left)
            self.__printTreeRec(node.right)
 
    def getRootHash(self) -> str: 
        return self.root.value
    
    def getAuthenticationPath(self, value, i_val):
        path = {}
        
        def findNode(node, depth, leaf_index):
            nonlocal i_val
            if node is None:
                return False
            
            if node.left is None and node.right is None:
                if leaf_index == i_val:
                    if i_val % 2 == 0:
                        path[str(depth)+"l"] = node.value
                    else:
                        path[str(depth)+"r"] = node.value
                    return True
                else:
                    return False
                
            else:
                if node.left and findNode(node.left, depth + 1, leaf_index * 2):
                    path[str(depth)+"r"] = node.right.value
                    return True
                elif node.right and findNode(node.right, depth + 1, leaf_index * 2 + 1):
                    path[str(depth)+"l"] = node.left.value
                    return True
                return False 

        findNode(self.root, 0, 0)
        path[str(len(path))+ "z"] = self.root.value

        return path
    
    def getAncestorslist(self, value):
        path = []
        def findNode(node, value):
            if node is None:
                return False
            elif node.value == value:
                return True
            else:
                if node.left and findNode(node.left, value):
                    path.append(node.left.value)
                    return True
                elif node.right and findNode(node.right, value):
                    path.append(node.right.value)
                    return True
                return False
        findNode(self.root, value)
        path.append(self.root.value)
        return path
    
def mixmerkletree(f_w_i):
    mtree = MerkleTree(f_w_i)
    # print("Root Hash: "+ mtree.getRootHash()+"\n")
    return mtree.getRootHash(), mtree

def Ver_merkle_path(auth_path, root_hash):
    skip_count = 0

    for key, value in auth_path.items():
        if skip_count >= 3:
            
            if key[1] == "l" :
                prev_hash = hashlib.sha256(auth_path[key].encode('utf-8') + prev_hash.encode('utf-8')).hexdigest()
            elif key[1] == "r" :
                prev_hash = hashlib.sha256(prev_hash.encode('utf-8') + auth_path[key].encode('utf-8')).hexdigest()
            
        else:
            if key[1] == "l" :
                value1 = auth_path[key]
            elif key[1] == "r" :
                value2 = auth_path[key]

            skip_count += 1

            if skip_count == 2 :
                prev_hash = hashlib.sha256(value1.encode('utf-8') + value2.encode('utf-8')).hexdigest()
                skip_count += 1

    if prev_hash == root_hash :
        return 1
    else :
        return 0

def printPoly(poly, n):
    polynomial_str = ""

    for i in range(n):
        if poly[i] != 0:
            polynomial_str += str(poly[i]) + "x^" + str(i) + " + "

    polynomial_str = polynomial_str[:-3]
    print(polynomial_str)

def evaluate_polynomial(coefficients, x):
    result = 0
    for i, coef in enumerate(coefficients):
        result += coef * (x ** (len(coefficients) - 1 - i))
    return result

def listToString(s):
    str1 = ""
    for ele in s:
        str1 += str(ele)
        str1 += ","
    str1 = str1[:len(str1)-1]
    return str1

def get_timestamp() :
    ct = datetime.datetime.now()
    ts = ct.timestamp()
    return ts