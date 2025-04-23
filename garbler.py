import otc
from Parties import *
import socket
import pickle
from Crypto.Random import get_random_bytes

def garbler(alice):
    # Alice creates labels for initial input wires and output wires of the Garbled Circuit
    labelg_0, labelg_1 = alice.generateLabel(), alice.generateLabel()
    labele_0, labele_1 = alice.generateLabel(), alice.generateLabel()
    labelo_0, labelo_1 = alice.generateLabel(), alice.generateLabel()
    inputList, outputList = [labelg_0, labelg_1, labele_0, labele_1], [labelo_0, labelo_1]

    # Alice selects 1 as her input
    alice.input = labelg_1

    # Create the andGate. Set its input and output wires
    # Generate the truth table for an andgate so the garbler can garble
    gate = andGate(1, inputList, outputList)
    andtruth = gate.getTruthTable()

    garbledTable = alice.garbleTruthTable(andtruth, inputList, outputList)
    gate.garbledTruthTable = garbledTable

    # Create the actual Garbled Circuit holding the gates, initial input wires, and final output wires
    garbledCircuit = GarbledCircuit([gate], inputList, outputList)

    # Generate data to send to Evaluator- Evaluator inputs
    data = {"Inputs": {"Garbler": alice.input,"Evaluator":[labele_0,labele_1]},
            "Outputs": {labelo_0: 0, labelo_1: 1},
            "GarbledTables": garbledTable
            }

    return data


# ---------------- Connect to listener to connect to Bob -----------------------------------------#
def beginConnection(alice, data, eval_labels):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 50002))
    server.listen(1)

    print("Garbler Waiting for connection...")
    conn, addr = server.accept()

    # Sending the circuit data to the evaluator
    conn.sendall(pickle.dumps(data))

    # Send otc public key to evaluator
    s = otc.send()
    public_key = s.public.to_base64()

    #Generate encrypted labels to send to evaluator
    k0, k1 = get_random_bytes(16), get_random_bytes(16)
    ciphertext_list = alice.encrypt_evaluator_labels(eval_labels, k0, k1)
    print(ciphertext_list)

    data = {
        "pk":public_key.encode(),
        "ciphertexts":ciphertext_list,
    }
    conn.sendall(pickle.dumps(data))
    #print("Sent public key: ", public_key, "of type ", type(public_key))

    # Receive encrypted query selection from evaluator
    selection = conn.recv(2048)
    selection = pickle.loads(selection)
    #print("Received selection: ", selection)

    # Reply with 2 possible labels to select
    #print("Sending k0: ",k0," and k1: ",k1)
    replies = s.reply(selection, k0, k1)
    conn.sendall(pickle.dumps(replies))

    print("Successfully sent replies")

    receivedOutput = conn.recv(2048)
    print("Received evaluated output: ", receivedOutput)
    answer = alice.getLabelMapping()[receivedOutput]
    print("Answer: ",answer)

def main():
    # Create the Garbler
    alice = GarblerParty()

    data = garbler(alice)
    eval_labels = data["Inputs"]["Evaluator"]
    data["Inputs"].pop("Evaluator")
    print("Data used: ",data)

    beginConnection(alice, data, eval_labels)

if __name__ == "__main__":
    main()
