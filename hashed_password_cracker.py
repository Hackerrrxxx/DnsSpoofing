import hashlib
import itertools
import string
from concurrent.futures import ThreadPoolExecutor

def crack_password(hashed_password, algorithm, max_length=10, char_set=string.ascii_letters + string.digits):
    """
    Crack a hashed password using a brute-force approach.

    Args:
        hashed_password (str): The hashed password to crack.
        algorithm (str): The hashing algorithm used (e.g. 'md5', 'sha1', 'sha256', 'sha512').
        max_length (int): The maximum length of the password to try (default: 10).
        char_set (str): The character set to use for the password (default: ASCII letters and digits).

    Returns:
        str: The cracked password, or None if not found.
    """
    # Define the hashing function based on the algorithm
    hash_func = getattr(hashlib, algorithm, None)
    if hash_func is None:
        raise ValueError("Unsupported algorithm")

    def try_passwords(length):
        for password in itertools.product(char_set, repeat=length):
            password_str = ''.join(password)
            hashed_password_try = hash_func(password_str.encode()).hexdigest()
            if hashed_password_try == hashed_password:
                return password_str
        return None

    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(try_passwords, length) for length in range(1, max_length + 1)]
        for future in futures:
            result = future.result()
            if result:
                return result

    return None

# Example usage
if __name__ == '__main__':
    hashed_password = "5d41402abc4"  # MD5 hash of "hello"
    algorithm = "md5"
    max_length = 5

    # Use a limited character set (only lowercase letters)
    char_set = string.ascii_lowercase
    cracked_password = crack_password(hashed_password, algorithm, max_length, char_set)

    if cracked_password:
        print(f"Cracked password: {cracked_password}")
    else:
        print("Password not found")