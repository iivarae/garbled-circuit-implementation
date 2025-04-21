import random

from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

#Circuit made is specifically for max(x,y)
#Only has access to own inputs before OT
class GarblerParty:
    def __init__(self):
        self.input = input
        self.labelMapping = {} #Mapping labels to their actual output value

    def generateLabel(self):
        return Fernet.generate_key()

    #Mapping of labels to actual bit values for each wire
    #Each gate should have 8 labels associated- 4 for 2 of each input, 4 for the different encrypted output wires
    def getLabelMapping(self):
        return self.labelMapping

    #Double encrypt output labels using input labels
    def encryptOutput(self,inputs,output):
        f1, f2 = Fernet(inputs[0]), Fernet(inputs[1])
        first = f1.encrypt(output)
        return f2.encrypt(first)

    def encrypt_evaluator_labels(self, eval_labels, k0, k1):
        cipher0, cipher1 = AES.new(k0, AES.MODE_ECB), AES.new(k1, AES.MODE_ECB)
        labele_0, labele_1 = eval_labels[0], eval_labels[1]
        ct0 = cipher0.encrypt(pad(labele_0, 16))
        ct1 = cipher1.encrypt(pad(labele_1, 16))
        return [ct0,ct1]

    #Garble the given truthTable
    #Inputs are the 4 input labels- 2 for 0 1 from garbler, 2 for 0 1 from evaluator
    def garbleTruthTable(self, truthTable, inputs, outputs):
        print("Inputs: ",inputs)
        print("Outputs: ",outputs)
        #Loop through each key
        for possibility in truthTable:
            #Assign each input a label
            for i in range(len(possibility) - 1):
                if i == 0:
                    if possibility[i] == 0:
                        possibility[i] = inputs[0]
                        self.labelMapping[inputs[0]] = 0
                    elif possibility[i] == 1:
                        possibility[i] = inputs[1]
                        self.labelMapping[inputs[1]] = 1
                else:
                    if possibility[i] == 0:
                        possibility[i] = inputs[2]
                        self.labelMapping[inputs[2]] = 0
                    elif possibility[i] == 1:
                        possibility[i] = inputs[3]
                        self.labelMapping[inputs[3]] = 1

        for possibility in truthTable:
            #Get input labels for curr possibility
            inputs = [possibility[0], possibility[1]]
            if possibility[2] == 0:
                self.labelMapping[outputs[0]] = 0
                encryptedOutputWire = self.encryptOutput(inputs,outputs[0])
                possibility[2] = encryptedOutputWire
            elif possibility[2] == 1:
                self.labelMapping[outputs[1]] = 1
                encryptedOutputWire = self.encryptOutput(inputs,outputs[1])
                possibility[2] = encryptedOutputWire

        #Permute the truth table
        random.shuffle(truthTable)
        return truthTable

class EvaluatorParty:
    def __init__(self, input):
        self.input = input

    def decryptcipher(self, key, ciphertext):
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext), 16)

    def evaluateResult(self, evaluatorLabel, garblerLabel, garbledTable):
        for possibility in garbledTable:
            if evaluatorLabel in possibility and garblerLabel in possibility:
                outputLabel = possibility[2]
                f1, f2 = Fernet(garblerLabel), Fernet(evaluatorLabel)
                item = f2.decrypt(outputLabel)
                item = f1.decrypt(item)
                return item

        print("Error: No row contains the given labels")
        return -1

#Build the Circuit to Garble
class GarbledCircuit:
    def __init__(self, gates, inputs, outputs):
        self.gates = gates
        self.inputs = inputs
        self.outputs = outputs

#Inputs is a list of inputs [i0, i1]
#Output is the gate result o0
#garbledTruth is determined by the GarblerParty class
class andGate:
    def __init__(self, id, inputs, output):
        self.id = id
        self.inputs = inputs
        self.output = output
        self.garbledTruthTable = []

    #Provide the truth table for an and gate
    def getTruthTable(self):
        truthTable = [[0, 0, 0], [0, 1, 0], [1, 0, 0], [1, 1, 1]]
        return truthTable

    #Set the garbled
    def setGarbledTruthTable(self, garbledTruth):
        self.garbledTruthTable = garbledTruth

class xorGate:
    def __init__(self, id, inputs, outputs):
        self.id = id
        self.input = inputs
        self.outputs = outputs
        self.garbledTruthTable = []

    def getTruthTable(self):
        truthTable = [[0, 0, 0], [1, 1, 0], [1, 0, 1], [0, 1, 1]]
        return truthTable

    def setGarbledTruthTable(self, garbledTruth):
        self.garbledTruthTable = garbledTruth

class Wire:
    def __init__(self,label, id):
        self.label = label
        self.id = id