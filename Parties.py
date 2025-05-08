import random
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class GarblerParty:
    def __init__(self):
        self.input = input
        self.labelMapping = {} #Mapping labels to their actual output value

    #Set the input for the garbler
    def setInput(self, inputList):
        while True:
            #for 2 bit inputs
            if len(inputList) > 4:
                garblerInputs = input("Enter a Number from 0-3: ")
                if garblerInputs in ("0", "1", "2", "3"):
                    garblerInputs = bin(int(garblerInputs))[2:].zfill(2)
                    print("Garbler Input in Binary: ",garblerInputs)
                    return [inputList[int(garblerInputs[0])], inputList[int(garblerInputs[1])+2]]
                else:
                    print("Incorrect input provided")
            #for 1 bit inputs
            elif len(inputList) <= 4:
                garblerInputs = input("Enter a Number from 0-1: ")
                if garblerInputs in ("0", "1"):
                    garblerInputs = bin(int(garblerInputs))[2:]
                    print("Garbler Input in Binary: ",garblerInputs)
                    return [inputList[int(garblerInputs[0])]]
                else:
                    print("Incorrect input provided")

    #Generate an output answer message depending on the filename
    def outputMessage(self, answer, filename):
        if filename == "Millionaire.json":
            message = "Evaluator has a larger input OR inputs are the same" if answer == "0" else "Garbler has a larger input"
        elif filename == "and.json":
            message = "Answer is "+str(answer)
        elif filename == "Max2.json":
            message = "Largest input is "+str(answer)
        elif  filename == "Max1.json":
            message = "Largest input is "+str(answer) if answer == "1" else "Inputs are the same"
        return message

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
        garbledTable = []
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
                garbledTable.append(encryptedOutputWire)
            #If output is 1, encrypt with input of 0
            elif possibility[1] == 1:
                self.labelMapping[outputs[1]] = 1
                encryptedOutputWire = self.encryptOutput(inputs[0],outputs[1])
                possibility[1] = encryptedOutputWire
                garbledTable.append(encryptedOutputWire)

        #Permuting the truth table
        random.shuffle(truthTable)
        return garbledTable

    #Garble the given truthTable
    def garbleTruthTable(self, truthTable, inputs, outputs):
        #Loop through each key
        garbledTable = []
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
                garbledTable.append(encryptedOutputWire)
            elif possibility[2] == 1:
                self.labelMapping[outputs[1]] = 1
                encryptedOutputWire = self.encryptOutput(inputs,outputs[1])
                possibility[2] = encryptedOutputWire
                garbledTable.append(encryptedOutputWire)

        #Permute the truth table
        random.shuffle(garbledTable)
        return garbledTable

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
    def __init__(self):
        self.input = input

    def setInput(self, length):
        while True:
            # for 2 bit inputs
            if length >= 4:
                evaluatorInput = input("Enter a Number from 0-3: ")
                if evaluatorInput in ("0", "1", "2", "3"):
                    evaluatorInput = bin(int(evaluatorInput))[2:].zfill(2)
                    self.input = [evaluatorInput[0], evaluatorInput[1]]
                    print("Evaluator Input in Binary: ", evaluatorInput)
                    break
                else:
                    print("Incorrect input provided")
            # for 1 bit inputs
            elif length < 4:
                evaluatorInput = input("Enter a Number from 0-1: ")
                if evaluatorInput in ("0", "1"):
                    evaluatorInput = bin(int(evaluatorInput))[2:]
                    print("Evaluator Input in Binary: ", evaluatorInput)
                    self.input = [evaluatorInput[0]]
                    break
                else:
                    print("Incorrect input provided")

    #Decrypt evaluator's label using the correct key delivered over OT
    def decryptcipher(self, key, ciphertext):
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext), 16)

    #Decrypt and return the correct output label given 1 input
    def evaluateNot(self, input, garbledTable):
        f1 = Fernet(input)
        for possibility in garbledTable:
            try:
                item = f1.decrypt(possibility)
                return item
            except:
                continue
        return -1

    def evaluateResult(self, evaluatorLabel, garblerLabel, garbledTable):
        for possibility in garbledTable:
            f1 = Fernet(garblerLabel)
            f2 = Fernet(evaluatorLabel)
            try:
                item = f1.decrypt(possibility)
                item = f2.decrypt(item)
                return item
            except:
                continue
        return -1

    #Evaluate an Entire circuit. Feed multiple gates into evaluateResult/evaluateNot
    def evaluateCircuit(self, evalutorWires, garblerWires, garbledData):
        gates = garbledData["Gates"]
        outputWires, finalOutput = [], []

        #Counts for input wires
        wireId = 1
        inputMap = {}

        # Convert inputs to lists in case they aren't already (in the case of 1 bit inputs)
        if not isinstance(evalutorWires, list):
            evalutorWires = [evalutorWires]
        if not isinstance(garblerWires, list):
            garblerWires = [garblerWires]

        # Add garbler wires to input mapping
        for wire in garblerWires:
            inputMap[wireId] = wire if isinstance(wire, Wire) else Wire(wire, wireId)
            wireId += 1

        # Add evaluator wires to input mapping
        for wire in evalutorWires:
            inputMap[wireId] = Wire(wire, wireId)
            wireId += 1

        for gate in gates:
            for i in range(len(gate.inputs)):
                input_id = gate.inputs[i] #Get the input so we can reference inputMap
                # Set gate inputs to appropriate input wires
                if input_id in inputMap:
                    gate.inputs[i] = inputMap[input_id]
                # Set gate outputs to appropriate wires
                else:
                    for output in outputWires:
                        if gate.inputs[i] == output.id:
                            gate.inputs[i] = output

            # Evaluate gate
            outputId = gate.output
            if len(gate.inputs) == 1:
                result = self.evaluateNot(gate.inputs[0].label, gate.garbledTruthTable)
                if result == -1:
                    return -1
                gate.output = Wire(result, outputId)
            else:
                result = self.evaluateResult(gate.inputs[0].label, gate.inputs[1].label, gate.garbledTruthTable)
                if result == -1:
                    return -1
                gate.output = Wire(result, outputId)

            outputWires.append(gate.output)

            if gate.output.id in garbledData["Outputs"]:
                finalOutput.append(gate.output)

        # Return the final output wire(s)
        if len(finalOutput) > 1:
            return finalOutput
        else:
            return finalOutput[0].label

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
