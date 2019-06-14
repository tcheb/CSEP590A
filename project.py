import random
import xml.etree.ElementTree as et
from Crypto.Util import number
from scipy.interpolate import lagrange
from itertools import combinations 
import math
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from numpy.polynomial.polynomial import Polynomial
import numpy
import os
import sys

backend = default_backend()

def pad(m):
    return m+chr(16-len(m)%16)*(16-len(m)%16)

def unpad(ct):
    return ct[:-ct[-1]]
'''    
class Group:
    def __init__(self):
        self.p = number.getPrime(512)
        self.q = number.getPrime(512)
        while self.q == self.p :
            self.q = number.getPrime(512)
        self.N = self.p * self.q
        self.phi = (self.p-1) * (self.q-1)
        self.g = 2
        
    def sample(self):
        x = random.randint(1,self.phi)
        sample = self.g
        for i in range(x):
            sample = (self.g * sample) % self.N
            
        return sample
'''

class DataDistribution:

    def __init__(self, tree):
        self.tree = tree
        self.root = tree.getroot()
        #self.N = number.getStrongPrime(512)
        self.N = number.getPrime(16)
        self.suppliers = []
        self.points = []
        self.policies = []
        self.keys = []
        self.shares = []
        self.points = dict()

    def generatePoints(self):
        for sup in self.suppliers:
            x = random.randint(1,self.N)
            y = random.randint(1,self.N)
            self.points[sup]=((x,y))
            
    #def getPossiblePolicyNb(self):
    #    nbSuppliers = len(self.suppliers)
    #    count = 0
    #    for i in range(nbSuppliers):
    #        count = count + (math.factorial(nbSuppliers)/(math.factorial(i+1)*math.factorial(nbSuppliers-i-1)))
    #    return int(count)
        
    def findPartByName(self, name):
        return self.root.find(".//Part[@Name='"+name+"']")

    def setNodeAccessPolicies(self, node, parentOwner):
        #rootOwner = self.root.get("Owner")
        nodeOwner = node.get("Owner")
        if nodeOwner not in self.suppliers and nodeOwner is not None:
            self.suppliers.append(nodeOwner)

        if nodeOwner is None and parentOwner is not None:
            nodeOwner = parentOwner
        
        policy = node.get("AccessPolicy")
        if policy is None:
            policy = ()
        
        if nodeOwner is not None:
            policy=policy+(nodeOwner,)

        node.set("AccessPolicy", policy)

        for child in list(node) :
            self.setNodeAccessPolicies(child, nodeOwner)
            
        interfacesWith = node.get("interfacesWith")
        if interfacesWith is not None and nodeOwner is not None:
            interface = self.findPartByName(interfacesWith)
            interfacePolicy = interface.get("AccessPolicy")
            if interfacePolicy is None or interfacePolicy == ():
                interfacePolicy = (nodeOwner,)
            else:
                interfacePolicy = interfacePolicy+(nodeOwner,)
            interface.set("AccessPolicy",interfacePolicy)

    def setTreeAccessPolicies(self):
        #rootOwner = self.root.get("Owner")
        #self.root.set("AccessPolicy", [rootOwner])
        self.root.set("AccessPolicy", ())
        for child in list(self.root) :
            self.setNodeAccessPolicies(child, None)
            
    def generatePolicies(self):
        nbSuppliers = len(self.suppliers)
        
        self.policies.append(())
        self.keys.append(random.randint(1,self.N))

        x1 = random.randint(1,self.N)
        y1 = random.randint(1,self.N)
        shares = [(x1,y1)]
        x2 = random.randint(1,self.N)
        y2 = random.randint(1,self.N)
        shares.append((x2,y2))
        self.shares.append(shares)
        
        for sup in self.suppliers:
            policy = (sup,)
            self.policies.append(policy)
            key = random.randint(1,self.N)
            self.keys.append(key)
            
            shares = []
            
            x1 = random.randint(1,self.N)
            y1 = random.randint(1,self.N)
            shares = [(x1,y1)]
            
            #xs = numpy.array([self.points[sup][0], x1, 0],dtype=numpy.uint64)
            #ys = numpy.array([self.points[sup][1], y1, key],dtype=numpy.uint64)
            xs = [self.points[sup][0], x1, 0]
            ys = [self.points[sup][1], y1, key]
            
            #poly = numpy.polyfit(xs,ys, 2)
            poly = lagrange(xs,ys)
            
            x2 = random.randint(1,self.N)
            y2 = poly(x2)
            #y2 = int(numpy.polyval(poly,x2))

            shares.append((x2,y2))
            self.shares.append(shares)
            
        combs = list(combinations(self.suppliers,2))
        for comb in combs:
            self.policies.append(comb)
            key = random.randint(1,self.N)
            self.keys.append(key)
            
            sup1 = comb[0]
            sup2 = comb[1]

            x = [self.points[sup1][0], self.points[sup2][0], 0]
            y = [self.points[sup1][1], self.points[sup2][1], key]
            poly = lagrange(x,y)

            shares = []

            x1 = random.randint(1,self.N)
            y1 = poly(x1)
            shares.append((x1,y1))

            x2 = random.randint(1,self.N)
            y2 = poly(x2)
            shares.append((x2,y2))
            self.shares.append(shares)

    def encryptTree(self):
        for child in list(self.root) :
            self.encryptNode(child)

    def encryptNode(self, node):
        policy = node.get("AccessPolicy")
        
        index = self.policies.index(policy)
        key = (self.keys[index]).to_bytes(16, byteorder='big')
        
        geometry = pad(node.get("Geometry")).encode('utf-8')

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(geometry) + encryptor.finalize()

        node.set("KeyShare",self.shares[index])

        node.set("Geometry",ct.hex())

        for child in list(node) :
            self.encryptNode(child)

    def saveTree(self, fileName):
        self.tree.write(fileName)
        
    def distributePoints(self):
        for sup in self.suppliers:
            point = self.points[sup]
            file = open(sup+".key", 'w')
            file.write(str(point[0]))
            file.write("\n")
            file.write(str(point[1]))
            file.close()
            
    def decryptTree(self, point):
        for child in list(self.root) :
            self.decryptNode(child, point)

    def decryptNode(self, node, point):
        points = eval(node.get("KeyShare"))
        
        x = [points[0][0], points[1][0], point[0]]
        y = [points[0][1], points[1][1], point[1]]
        poly = lagrange(x,y)

        key = int(poly(0))
        
        if key > 0:
            key = key.to_bytes(16, byteorder='big')

            geometry = bytes.fromhex(node.get("Geometry"))

            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
            decryptor = cipher.decryptor()
            pt = unpad(decryptor.update(geometry) + decryptor.finalize())
            
            node.set("Geometry", pt.decode('utf-8'))

        for child in list(node) :
            self.decryptNode(child, point)

if len(sys.argv) < 3 or (sys.argv[1] == 'd' and len(sys.argv) != 4):
    print("usage: project mode xmlFileName [keyFileName]")
    print("mode: e=encrypt / d=decrypt")
    sys.exit(1)

mode = sys.argv[1]
xml = sys.argv[2]

tree = et.parse(xml)    

# initializing the data distribution from the input xml
dd = DataDistribution(tree)

'''
DECRYPTION
'''
if mode == 'd':
    keyFileName = sys.argv[3]
    sup = os.path.splitext(keyFileName)[0]
    
    file = open(keyFileName,'r')
    lines = file.readlines()
    point = tuple([int(x) for x in lines])
    
    dd.decryptTree(point)
    dd.saveTree("Volvo_decrypted" + sup + ".xml")

'''
ENCRYPTION
'''
if mode == 'e':
    # setting the access policy arrays based on ownership and interfaces
    dd.setTreeAccessPolicies()
    dd.generatePoints()
    dd.generatePolicies()
    dd.encryptTree()
    dd.saveTree("Volvo_encrypted.xml")
    dd.distributePoints()
