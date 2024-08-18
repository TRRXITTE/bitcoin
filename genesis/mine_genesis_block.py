import hashlib
import time

def calculate_hash(index, previous_hash, timestamp, data, nonce):
    value = str(index) + previous_hash + str(timestamp) + data + str(nonce)
    return hashlib.sha256(value.encode()).hexdigest()

def mine_genesis_block(difficulty):
    index = 0
    previous_hash = '0' * 64  # Typically the hash of the previous block, for genesis it is usually all zeros.
    timestamp = int(time.time())
    data = "tBTC 18th August 2024"
    nonce = 0

    difficulty_target = '0' * difficulty

    print(f"Mining genesis block with difficulty target: {difficulty_target}")

    while True:
        hash_value = calculate_hash(index, previous_hash, timestamp, data, nonce)
        if hash_value[:difficulty] == difficulty_target:
            print(f"Genesis Block mined!")
            print(f"Hash: {hash_value}")
            print(f"Nonce: {nonce}")
            print(f"Timestamp: {timestamp}")
            break
        nonce += 1

    genesis_block = {
        'index': index,
        'previous_hash': previous_hash,
        'timestamp': timestamp,
        'data': data,
        'nonce': nonce,
        'hash': hash_value
    }

    return genesis_block

if __name__ == "__main__":
    difficulty = 4  # Adjust difficulty level as needed
    genesis_block = mine_genesis_block(difficulty)
    print(genesis_block)
