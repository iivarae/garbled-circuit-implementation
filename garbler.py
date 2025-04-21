import json
import sys
import otc
from Parties import *
import socket
import pickle
from Crypto.Random import get_random_bytes

def readCircuitData(alice):
    with open("Max.json") as fp:
        data = json.load(fp)

    #Generate labels for every wire in the Circuit
    wireList = []
    inputList = []
    outputList = []
    for i in range(len(data["Wires"])):
        wire = Wire(alice.generateLabel(), i+1)
        wire2 = Wire(alice.generateLabel(), i+1)
        #Generate 2 possible labels for all wires
        wireList.append(wire)
        wireList.append(wire2)
        #Generate 2 possible labels for input wires
        if data["Wires"][i] in data["Inputs"]:
            inputList.append(wire)
            inputList.append(wire2)
        #Generate 2 possible output values
        elif data["Wires"][i] == data["Output"]:
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
    for input in circuitData["Inputs"]:
        print("Input: ",input.label)
    for wire in circuitData["Wires"]:
        print("Wire: ",wire.id, wire.label)

    # Alice selects wire 1 as her input
    alice.input = inputList[0]

    # Create the circuit by garbling each gate's truth table
    garbledTables = alice.createGarbledCircuit(circuitData["Wires"], circuitData["Gates"])

    # Generate data to send to Evaluator- Evaluator inputs
    data = {
            "Inputs": {"Garbler": alice.input,"Evaluator":[inputList[2],inputList[3]]},
            "Outputs": {outputList[0].label: 0, outputList[1].label: 1},
            "GarbledTables": garbledTables,
            "Gates": circuitData["Gates"]
            }
    print("Input Data: ",data["Inputs"])
    return data

# ---------------- Connect to listener to connect to Bob -----------------------------------------#
def beginConnection(alice, data, eval_labels):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 50002))
    server.listen(1)

    print("Garbler Waiting for connection...")
    conn, addr = server.accept()

    # Sending the circuit data to the evaluator
    dataLength = len(pickle.dumps(data))
    conn.sendall(dataLength.to_bytes(4, byteorder='big'))
    conn.sendall(pickle.dumps(data))

    # Send otc public key to evaluator
    s = otc.send()
    public_key = s.public.to_base64()

    #Generate encrypted labels to send to evaluator
    #Because OTC library only allows 16 bits to be obliviously transferred, send one of 2 16 bit keys to decrypt the correct label
    k0, k1 = get_random_bytes(16), get_random_bytes(16)
    ciphertext_list = alice.encrypt_evaluator_labels(eval_labels, k0, k1)

    data = {
        "pk":public_key.encode(),
        "ciphertexts":ciphertext_list,
    }
    conn.sendall(pickle.dumps(data))

    # Receive encrypted query selection from evaluator from oblivious transfer
    selection = conn.recv(4096)
    selection = pickle.loads(selection)

    # Reply with 2 possible labels to select
    replies = s.reply(selection, k0, k1)
    conn.sendall(pickle.dumps(replies))
    print("Obliviously Transferred 2 input options to evaluator")

    #Receive result of evaluating the circuit
    receivedOutput = conn.recv(4096)
    print("Received evaluated output: ", receivedOutput)
    answer = alice.getLabelMapping()[receivedOutput]
    print("Answer: ",answer)
    conn.sendall(answer.to_bytes(answer, byteorder='big'))

def main():
    # Create the Garbler
    alice = GarblerParty()
    circuitData = readCircuitData(alice)

    data = garble(alice, circuitData)
    eval_labels = data["Inputs"]["Evaluator"]
    data["Inputs"].pop("Evaluator")

    beginConnection(alice, data, eval_labels)

if __name__ == "__main__":
    main()
