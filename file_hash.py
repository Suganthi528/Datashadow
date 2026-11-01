import hashlib


def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            data = file.read(4096)

            if not data:
                break

            sha256_hash.update(data)

    return sha256_hash.hexdigest()