from Parties import EvaluatorParty
import socket
import pickle
import otc
from oblivious.ristretto import point #Needed to correctly serialize public key

input = binaryinput1 = bin(1)[2:].zfill(1)
bob = EvaluatorParty(input)

HOST = '127.0.0.1'
PORT = 50007

# Listen for Alice's Data- get the Circuit from her
garbledTruth = []
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.bind(('127.0.0.1', PORT))
client.connect((HOST, 50002))
print("Connected to Alice")

with client as conn:
    #Receiving the garbled data
    data = conn.recv(2048)
    garbledData = pickle.loads(data)
    print("Received Inputs: ", garbledData["Inputs"])

    # Receive public key for Oblivious Transfer
    receivedData = pickle.loads(client.recv(2048))
    pk = point.from_base64(receivedData["pk"])
    ciphertexts = receivedData["ciphertexts"]

    #Select which input he wants, label for 0 or label for 1
    r = otc.receive()
    query = r.query(pk, int(input))
    client.sendall(pickle.dumps(query))
    #print("Sent choice: ",query)

    #Receive 2 choices
    replies = conn.recv(2048)
    replies = pickle.loads(replies)

    #Receive the key for encrypted label
    key = r.elect(pk, int(input), *replies)
    evaluatorLabel = bob.decryptcipher(key, receivedData["ciphertexts"][int(input)])

    garblerLabel = garbledData["Inputs"]["Garbler"]
    print("Actual Evaluator Label: ",evaluatorLabel)
    print("Garbler's Label: ",garblerLabel)

    #Evaluator now has to evaluate the circuit
    garbledTable = garbledData["GarbledTables"]
    output = bob.evaluateResult(evaluatorLabel, garblerLabel, garbledTable)
    print("Discovered output: ",output)
    if output == -1:
        print("Output not found- closing connection")
        conn.close()

    conn.sendall(output)