import json
import sys
import otc
from Parties import *
import socket
import pickle
from Crypto.Random import get_random_bytes

#Read circuit data and generate labels for wires
def readCircuitData(alice, filename):
    with open(filename) as fp:
        data = json.load(fp)

    #Generate labels for every wire in the Circuit
    wireList, inputList, outputList = [], [], []
    for i in range(len(data["Wires"])):
        #Generate 2 possible labels for all wires
        wire, wire2 = Wire(alice.generateLabel(), i+1), Wire(alice.generateLabel(), i+1)
        wireList.append(wire)
        wireList.append(wire2)

        #Add generated labels to inputList
        if data["Wires"][i] in data["Inputs"]:
            inputList.append(wire)
            inputList.append(wire2)

        #Add generated labels to outputList
        elif data["Wires"][i] in data["Output"]:
            outputList.append(wire)
            outputList.append(wire2)

    gateList = []
    #Create gate classes according to inputs
    for gate in data["Gates"].keys():
        gateType = data["Gates"][gate]["type"]
        gateInputs = data["Gates"][gate]["inputs"]
        gateOutput = data["Gates"][gate]["output"]
        cls = getattr(sys.modules[__name__], gateType)
        instance = cls(data["Gates"][gate]["id"], data["Gates"][gate]["type"][:-4], gateInputs, gateOutput)
        gateList.append(instance)

    return {"Wires":wireList, "Gates":gateList, "Inputs":inputList, "Outputs":outputList}

def garble(alice, circuitData):
    inputList, outputList = circuitData["Inputs"], circuitData["Outputs"]

    #Provide an input
    alice.input = alice.setInput(inputList)

    # Create the garbledCircuit
    garbledTables = alice.createGarbledCircuit(circuitData["Wires"], circuitData["Gates"])

    #print("Garbled Tables:")
    #for table in garbledTables:
    #    print("Table: ",table)

    # Generate data to send to Evaluator- Evaluator inputs
    # Evaluator can have the Output IDs and garbler's input label. Evaluator input labels are removed in main function before sending
    # Providing input/output wire id's to evaluator is just a more organized way to send circuit data to the evaluator

    #Output/input list of labels changes depending on if inputs/outputs are 1 or 2 bits long
    evalInputs = [inputList[4],inputList[5],inputList[6],inputList[7]] if len(inputList) > 4 else [inputList[2],inputList[3]]
    outList = [outputList[0].id, outputList[1].id,outputList[2].id,outputList[3].id] if len(outputList) > 2 else [outputList[0].id]

    data = {
            "Inputs": {"Garbler": alice.input,"Evaluator": evalInputs},
            "Outputs": outList,
            "GarbledTables": garbledTables,
            "Gates": circuitData["Gates"]
            }
    return data

# ---------------- Connect to Bob -----------------------------------------#
def beginConnection(alice, data, eval_labels, filename):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 50003))
    server.listen(1)

    print("Garbler Waiting for Evaluator's connection...")
    conn, addr = server.accept()

    # Sending the circuit data to the evaluator
    dataLength = len(pickle.dumps(data))
    conn.sendall(dataLength.to_bytes(4, byteorder='big'))
    conn.sendall(pickle.dumps(data))

    #Send 2 encrypted labels to the evaluator
    for i in range(int(len(eval_labels) / 2)):
        # Send otc public key to evaluator
        s = otc.send()
        public_key = s.public.to_base64()

        # Because OTC library only allows 16 bits to be obliviously transferred, send one of 2 16 bit keys to decrypt the correct label
        k0, k1 = get_random_bytes(16), get_random_bytes(16)
        if len(eval_labels) > 2 and i == 1:
            ciphertext_list = alice.encrypt_evaluator_labels(eval_labels[2], eval_labels[3], k0, k1)
        else:
            ciphertext_list = alice.encrypt_evaluator_labels(eval_labels[0],eval_labels[1], k0, k1)

        keyData = {"pk":public_key.encode(),"ciphertexts":ciphertext_list}
        conn.sendall(pickle.dumps(keyData))

        # Receive encrypted query selection from evaluator via oblivious transfer
        selection = conn.recv(4096)
        selection = pickle.loads(selection)

        # Reply with 2 possible keys to select- evaluator will choose the appropriate key to decrypt his label
        replies = s.reply(selection, k0, k1)
        conn.sendall(pickle.dumps(replies))

    #Receive result of evaluating the circuit
    receivedOutput = pickle.loads(conn.recv(4096))
    print("Received output: ",receivedOutput)
    answer = ""

    if len(data["Outputs"]) >= 2:
        for output in receivedOutput:
            answer += str(alice.getLabelMapping()[output])
        answer = int(answer, 2)
    else:
        answer = str(alice.getLabelMapping()[receivedOutput])

    message = alice.outputMessage(answer, filename)

    conn.sendall(pickle.dumps({"answer":message}))
    print("Message: ",message)

def main(filename):
    # Create the Garbler
    alice = GarblerParty()
    circuitData = readCircuitData(alice,filename)

    data = garble(alice, circuitData)
    eval_labels = data["Inputs"]["Evaluator"]
    data["Inputs"]["Evaluator"] = [wire.id for wire in data["Inputs"]["Evaluator"]]

    beginConnection(alice, data, eval_labels, filename)

if __name__ == "__main__":
    main("Millionaire.json")
