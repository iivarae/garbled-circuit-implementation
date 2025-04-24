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

    #Provide a 2 bit input
    while True:
        garblerInputs = input("Enter a Number from 0-3: ")
        if garblerInputs in ("0", "1", "2", "3"):
            garblerInputs = bin(int(garblerInputs))[2:].zfill(2)
            print("Garbler Input in Binary: ",garblerInputs)
            alice.input = [inputList[int(garblerInputs[0])], inputList[int(garblerInputs[1])+2]]
            break
        else:
            print("Incorrect input provided")


    # Create the circuit by garbling each gate's truth table
    garbledTables = alice.createGarbledCircuit(circuitData["Wires"], circuitData["Gates"])

    # Generate data to send to Evaluator- Evaluator inputs
    data = {
            "Inputs": {"Garbler": alice.input,"Evaluator":[inputList[4],inputList[5],inputList[6],inputList[7]]},
            "Outputs": [outputList[0].id, outputList[1].id,outputList[2].id,outputList[3].id],
            "GarbledTables": garbledTables,
            "Gates": circuitData["Gates"]
            }
    return data

# ---------------- Connect to Bob -----------------------------------------#
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


    #Generate 2 encrypted labels for the evaluator to choose from
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

    #Receive result of evaluating the circuit
    receivedOutput = pickle.loads(conn.recv(4096))

    answer = ""
    for output in receivedOutput:
        answer += str(alice.getLabelMapping()[output])
    answer = int(answer, 2)

    conn.sendall(pickle.dumps({"answer":answer}))
    print("Largest Number Entered: ",answer)

def main():
    # Create the Garbler
    alice = GarblerParty()
    circuitData = readCircuitData(alice)

    data = garble(alice, circuitData)
    eval_labels = data["Inputs"]["Evaluator"]
    data["Inputs"]["Evaluator"] = [wire.id for wire in data["Inputs"]["Evaluator"]]

    beginConnection(alice, data, eval_labels)

if __name__ == "__main__":
    main()
