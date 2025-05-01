from Parties import EvaluatorParty
import socket
import pickle
import otc
from oblivious.ristretto import point  # Needed to correctly serialize public key
import json

def evaluate():
    with open("and.json") as fp:
        circuitData = json.load(fp)

    while True:
        #for 2 bit inputs
        if len(circuitData["Inputs"]) >= 4:
            evaluatorInput = input("Enter a Number from 0-3: ")
            if evaluatorInput in ("0", "1", "2", "3"):
                evaluatorInput = bin(int(evaluatorInput))[2:].zfill(2)
                inputList = [evaluatorInput[0], evaluatorInput[1]]
                print("Evaluator Input in Binary: ", evaluatorInput)
                break
            else:
                print("Incorrect input provided")
        #for 1 bit inputs
        elif len(circuitData["Inputs"]) < 4:
            evaluatorInput = input("Enter a Number from 0-1: ")
            if evaluatorInput in ("0", "1"):
                evaluatorInput = bin(int(evaluatorInput))[2:]
                print("Evaluator Input in Binary: ", evaluatorInput)
                inputList = [evaluatorInput[0]]
                break
            else:
                print("Incorrect input provided")

    bob = EvaluatorParty()
    bob.input = inputList

    HOST = '127.0.0.1'
    PORT = 50005

    # Listen for Alice's Data- get the Circuit from her
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.bind(('127.0.0.1', PORT))
    client.connect((HOST, 50003))
    print("Connected to Garbler")

    with client as conn:
        # Receiving the garbled data
        expectedLength = conn.recv(4)
        expectedLength = int.from_bytes(expectedLength, byteorder='big')

        # Receive entire pickled data based on the received length
        received_data = b""
        while len(received_data) < expectedLength:
            chunk = conn.recv(expectedLength - len(received_data))
            if not chunk:
                break
            received_data += chunk

        garbledData = pickle.loads(received_data)

        # Select which input he wants, label for 0 or label for 1
        evaluatorLabels = []
        for i in range(int(len(garbledData["Inputs"]["Evaluator"]) / 2)):
            # Receive public key for Oblivious Transfer
            receivedData = pickle.loads(client.recv(4096))
            pk = point.from_base64(receivedData["pk"])

            r = otc.receive()
            query = r.query(pk, int(inputList[i]))
            client.sendall(pickle.dumps(query))

            # Receive 2 encrypted choices
            replies = conn.recv(4096)
            replies = pickle.loads(replies)

            # Receive the key for encrypted label to decrypt
            # Input = 0 or 1
            key = r.elect(pk, int(inputList[i]), *replies)
            evaluatorLabel = bob.decryptcipher(key, receivedData["ciphertexts"][int(inputList[i])])
            evaluatorLabels.append(evaluatorLabel)

        garblerLabels = garbledData["Inputs"]["Garbler"]
        # Evaluator now has to evaluate the circuit
        output = bob.evaluateCircuit(evaluatorLabels, garblerLabels, garbledData)
        print("Output: ",output)
        if output == -1:
            print("Output not found- closing connection")
            conn.close()
        #For handling an output of 2 bits
        if len(garbledData["Outputs"]) >= 2:
            output = [outputs.label for outputs in output]
        #For handling an output of 1 bit that is in a list
        if len(output) == 1:
            output = output[0].label

        conn.sendall(pickle.dumps(output))
        outputval = pickle.loads(conn.recv(2048))

        print(outputval["answer"])

def main():
    evaluate()

if __name__ == "__main__":
    main()
