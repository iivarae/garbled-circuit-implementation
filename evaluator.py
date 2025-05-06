from Parties import EvaluatorParty
import socket
import pickle
import otc
from oblivious.ristretto import point  # Needed to correctly serialize public key for otc
import time

def evaluate():
    bob = EvaluatorParty()

    # Connect to Alice and get the circuit data from her
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 50003))
    print("Connected to Garbler")

    with client as conn:
        # Receiving the length of the garbled data
        expectedLength = int.from_bytes(conn.recv(4), byteorder='big')

        # Receive entire pickled data based on the received length
        received_data = b""
        while len(received_data) < expectedLength:
            chunk = conn.recv(expectedLength - len(received_data))
            if not chunk:
                break
            received_data += chunk

        garbledData = pickle.loads(received_data)

        #Choose input
        bob.setInput(len(garbledData["Inputs"]["Evaluator"]) + len(garbledData["Inputs"]["Garbler"]))

        start_time = time.perf_counter()

        # Select which input he wants, label for 0 or label for 1
        evaluatorLabels = []
        for i in range(int(len(garbledData["Inputs"]["Evaluator"]) / 2)):
            # Receive public key for Oblivious Transfer
            receivedData = pickle.loads(client.recv(4096))
            pk = point.from_base64(receivedData["pk"])

            r = otc.receive()
            query = r.query(pk, int(bob.input[i]))
            client.sendall(pickle.dumps(query))

            # Receive 2 ENCRYPTED choices
            replies = conn.recv(4096)
            replies = pickle.loads(replies)

            # Receive the key to decrypt the correct encrypted label. Send 0 or 1 as input
            key = r.elect(pk, int(bob.input[i]), *replies)
            evaluatorLabel = bob.decryptcipher(key, receivedData["ciphertexts"][int(bob.input[i])])
            evaluatorLabels.append(evaluatorLabel)

        garblerLabels = garbledData["Inputs"]["Garbler"]

        # Evaluator now has to evaluate the circuit
        output = bob.evaluateCircuit(evaluatorLabels, garblerLabels, garbledData)

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
        client.close()
        end_time = time.perf_counter()
        execution_time = end_time - start_time
        print("Time: ",execution_time)

def main():
    evaluate()

if __name__ == "__main__":
    main()
