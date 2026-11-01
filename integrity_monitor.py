from file_hash import calculate_file_hash


def check_file_integrity(file_path, stored_hash):

    current_hash = calculate_file_hash(file_path)

    if current_hash == stored_hash:
        return True, "INTEGRITY OK"

    return False, "FILE MODIFIED"