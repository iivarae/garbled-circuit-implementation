import random
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class GarblerParty:
    def __init__(self):
        self.input = input
        self.labelMapping = {} #Mapping labels to their actual output value

    #Generate labels for each wire
    def generateLabel(self):
        return Fernet.generate_key()

    #Mapping of labels to actual bit values for each wire possibility
    def getLabelMapping(self):
        return self.labelMapping

    #Double encrypt output labels using 2 input labels
    def encryptOutput(self,inputs,output):
        if len(inputs) == 2:
            f1, f2 = Fernet(inputs[0]), Fernet(inputs[1])
            first = f1.encrypt(output)
            return f2.encrypt(first)
        #Encrypting a NOT Gate's output
        else:
            f1 = Fernet(inputs)
            return f1.encrypt(output)

    #Encrypting evaluator labels to send over OT- Evaluator SHOULD NOT learn both labels, only one. Mask this with encryption
    def encrypt_evaluator_labels(self, eval_label0, eval_label1, k0, k1):
        cipher0, cipher1 = AES.new(k0, AES.MODE_ECB), AES.new(k1, AES.MODE_ECB)
        labele_0, labele_1 = eval_label0.label, eval_label1.label
        ct0 = cipher0.encrypt(pad(labele_0, 16))
        ct1 = cipher1.encrypt(pad(labele_1, 16))
        return [ct0,ct1]

    #garble a Not Gate's truth table
    def garbleNot(self, truthTable, inputs, outputs):
        for possibility in truthTable:
            if possibility[0] == 0:
                possibility[0] = inputs[0]
                self.labelMapping[inputs[0]] = 0
            elif possibility[0] == 1:
                possibility[0] = inputs[1]
                self.labelMapping[inputs[1]] = 1

        #Encrypt output with single input
        for possibility in truthTable:
            #If output is 0, encrypt with input of 1
            if possibility[1] == 0:
                self.labelMapping[outputs[0]] = 0
                encryptedOutputWire = self.encryptOutput(inputs[1],outputs[0])
                possibility[1] = encryptedOutputWire
            #If output is 1, encrypt with input of 0
            elif possibility[1] == 1:
                self.labelMapping[outputs[1]] = 1
                encryptedOutputWire = self.encryptOutput(inputs[0],outputs[1])
                possibility[1] = encryptedOutputWire

        #Permuting the truth table
        random.shuffle(truthTable)
        return truthTable

    #Garble the given truthTable
    def garbleTruthTable(self, truthTable, inputs, outputs):
        #Loop through each key
        for possibility in truthTable:
            #Map each label to a value so that the final output can be relayed
            #Garbler should know the values of labels anyhow
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

    def createGarbledCircuit(self, wires, gates):
        garbledTables = []
        for gate in gates:
            truth = gate.getTruthTable()
            # Set input/outputs for the current gate
            gateInputs, gateOutput = [], []
            for wire in wires:
                if wire.id in gate.inputs:
                    gateInputs.append(wire.label)
                if wire.id == gate.output:
                    gateOutput.append(wire.label)

            # Garble a gate's table. Split Not and others since not takes 1 input vs 2
            if gate.type == "not":
                garbledTable = self.garbleNot(truth, gateInputs, gateOutput)
                gate.garbledTruthTable = garbledTable
                garbledTables.append(garbledTable)
            else:
                garbledTable = self.garbleTruthTable(truth, gateInputs, gateOutput)
                gate.garbledTruthTable = garbledTable
                garbledTables.append(garbledTable)
        return garbledTables

class EvaluatorParty:
    def __init__(self, input):
        self.input = input

    #Decrypt evaluator's label using the correct key delivered over OT
    def decryptcipher(self, key, ciphertext):
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext), 16)

    #Decrypt and return the correct output label given 2 inputs
    def evaluateResult(self, evaluatorLabel, garblerLabel, garbledTable):
        for possibility in garbledTable:
            if evaluatorLabel in possibility and garblerLabel in possibility:
                outputLabel = possibility[2]
                f1, f2 = Fernet(garblerLabel), Fernet(evaluatorLabel)
                item = f2.decrypt(outputLabel)
                item = f1.decrypt(item)
                return item
        #print("Error: No row contains the given labels")
        return -1

    #Decrypt and return the correct output label given 1 input
    def evaluateNot(self, input, garbledTable):
        #print("Evaluating: ",input)
        for possibility in garbledTable:
            if input == possibility[0]:
                outputLabel = possibility[1]
                f1 = Fernet(input)
                item = f1.decrypt(outputLabel)
                #print("Output found: ", item)
                return item
        #print("Error- possibility not found in truth Table")
        return -1

    # Decrypt and return the correct output label with 2+ circuit inputs
    def evaluateResultTwo(self, evaluatorLabel, garblerLabel, garbledTable):
        #print("Evaluating ",evaluatorLabel, garblerLabel)
        for possibility in garbledTable:
            if evaluatorLabel in possibility and garblerLabel in possibility:
                outputLabel = possibility[2]
                f1, f2 = Fernet(garblerLabel), Fernet(evaluatorLabel)
                item = f1.decrypt(outputLabel)
                item = f2.decrypt(item)
                #print("Output found: ", item)
                return item
        #print("Error: No row contains the given labels")
        return -1

    def evaluateCircuitTwo(self, evaluatorLabels, garblerLabels, garbledData):
        gates = garbledData["Gates"]
        outputWires = []
        evaluatorWire3 = Wire(evaluatorLabels[0], 3)
        evaluatorWire4 = Wire(evaluatorLabels[1], 4)
        finalOutput = []
        for gate in gates:
            for i in range(len(gate.inputs)):
                if gate.inputs[i] == 1:
                    gate.inputs[i] = garblerLabels[0]
                elif gate.inputs[i] == 2:
                    gate.inputs[i] = garblerLabels[1]
                elif gate.inputs[i] == 3:
                    gate.inputs[i] = evaluatorWire3
                elif gate.inputs[i] == 4:
                    gate.inputs[i] = evaluatorWire4
                else:
                    for output in outputWires:
                        if gate.inputs[i] == output.id:
                            gate.inputs[i] = output
            # Evaluate on not Gate
            if len(gate.inputs) == 1:
                outputId = gate.output
                gate.output = Wire(self.evaluateNot(gate.inputs[0].label, gate.garbledTruthTable), outputId)
                outputWires.append(gate.output)
                if gate.output.id in garbledData["Outputs"]:
                    #print("--- One of final output wires found --")
                    finalOutput.append(gate.output)
            # Evaluate on all other gates w 2 inputs
            else:
                outputId = gate.output
                gate.output = Wire(
                    self.evaluateResultTwo(gate.inputs[0].label, gate.inputs[1].label, gate.garbledTruthTable), outputId)
                outputWires.append(gate.output)
                #print("Output id: ",gate.output.id)
                if gate.output.id in garbledData["Outputs"]:
                    #print("--- One of final output wires found --")
                    finalOutput.append(gate.output)
        return finalOutput

    #Evaluate an Entire circuit. Feed multiple gates into evaluateResult/evaluateNot
    def evaluateCircuit(self, evaluatorLabel, garblerWire, garbledData):
        evaluatorWire = Wire(evaluatorLabel, 2)
        length = len(evaluatorLabel)+len(garblerWire)

        if length == 4:
            return self.evaluateCircuitTwo(evaluatorLabel, garblerWire, garbledData)
        else:
            gates = garbledData["Gates"]
            outputWires = []

            for gate in gates:
                for i in range(len(gate.inputs)):
                    if gate.inputs[i] == 2:
                        gate.inputs[i] = evaluatorWire
                    elif gate.inputs[i] == 1:
                        gate.inputs[i] = garblerWire
                    else:
                        for output in outputWires:
                            if gate.inputs[i] == output.id:
                                gate.inputs[i] = output
                #Evaluate on not Gate
                if len(gate.inputs) == 1:
                    outputId = gate.output
                    gate.output = Wire(self.evaluateNot(gate.inputs[0].label, gate.garbledTruthTable), outputId)
                    outputWires.append(gate.output)
                #Evaluate on all other gates w 2 inputs
                else:
                    outputId = gate.output
                    gate.output = Wire(self.evaluateResult(gate.inputs[0].label, gate.inputs[1].label, gate.garbledTruthTable), outputId)
                    outputWires.append(gate.output)
            return outputWires[-1].label

#Inputs is a list of inputs [i0, i1]
#Output is the gate result o0
#garbledTruth is determined by the GarblerParty class
class andGate:
    def __init__(self, id, type, inputs, output):
        self.id = id
        self.type = type
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
    def __init__(self, id, type, inputs, output):
        self.id = id
        self.type = type
        self.inputs = inputs
        self.output = output
        self.garbledTruthTable = []

    def getTruthTable(self):
        truthTable = [[0, 0, 0], [1, 1, 0], [1, 0, 1], [0, 1, 1]]
        return truthTable

    def setGarbledTruthTable(self, garbledTruth):
        self.garbledTruthTable = garbledTruth

class notGate:
    def __init__(self, id, type, inputs, output):
        self.id = id
        self.type = type
        self.inputs = inputs
        self.output = output
        self.garbledTruthTable = []

    def getTruthTable(self):
        truthTable = [[0,1],[1,0]]
        return truthTable

    def setGarbledTruthTable(self, garbledTruth):
        self.garbledTruthTable = garbledTruth

class orGate:
    def __init__(self, id, type, inputs, output):
        self.id = id
        self.type = type
        self.inputs = inputs
        self.output = output
        self.garbledTruthTable = []

    def getTruthTable(self):
        truthTable = [[0,1,1],[1,0,1],[1,1,1],[0,0,0]]
        return truthTable

    def setGarbledTruthTable(self, garbledTruth):
        self.garbledTruthTable = garbledTruth

class xnorGate:
    def __init__(self, id, type, inputs, output):
        self.id = id
        self.type = type
        self.inputs = inputs
        self.output = output
        self.garbledTruthTable = []

    def getTruthTable(self):
        truthTable = [[0,0,1],[0,1,0],[1,0,0],[1,1,1]]
        return truthTable

    def setGarbledTruthTable(self, garbledTruth):
        self.garbledTruthTable = garbledTruth

class Wire:
    def __init__(self,label, id):
        self.label = label
        self.id = id