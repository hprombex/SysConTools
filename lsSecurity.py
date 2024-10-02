# Copyright (c) 2018-2024 hprombex
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# Author: hprombex

"""Module for Security class."""

import base64
import json
import os
import hashlib
from getpass import getpass

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken

from lsLog import Log


class SecurityInvalidPasswordError(Exception):
    """Custom exception for invalid password."""


class Security:
    """
    Handles secure phrase encryption and key management.

    Example:
    >>> passwd_sec = Security("passwd")
    >>> password = passwd_sec.manage_phrase()

    with custom message and skip question to overwrite the existing secure phrase:
    >>> password = passwd_sec.manage_phrase(overwrite_phrase=False, message="Please provide password")
    """

    ENCRYPTED_SECURE_PHRASE_FILE = "encrypted.phrase"
    KEY_FILE = "encryption.key"

    MASTER_PASSWORD_FILE = "encryption.key.master"
    MASTER_PASSWORD_FILE_SKIP = "key.master.skip"

    JSON_FILE = "security_data.json"

    def __init__(self, module_name: str = None, logger: Log = None):
        """
        Initializes a Security instance with optional module-specific settings for
        encryption and secure phrase management.

        :param module_name: An optional string representing the module name.
                            This is used to create unique key and secure
                            phrase names. If provided, it appends a short hash
                            based on the module name to these file names.
        :param logger: An optional Log instance for logging.
        """
        if logger:
            self.log = logger
        else:
            self.log = Log(store=False, timestamp=True)

        self._module_name = module_name
        self._fernet = None
        self._master_password: bytes = self._open_master_password()
        self._mp_fernet = Fernet(
            base64.urlsafe_b64encode(self._master_password)
        )

        if self._module_name:
            name = os.path.basename(self._module_name)
            short_hash = self._generate_short_hash(name)
            self.KEY_FILE = f"{self.KEY_FILE}.{short_hash}"
            self.ENCRYPTED_SECURE_PHRASE_FILE = (
                f"{self.ENCRYPTED_SECURE_PHRASE_FILE}.{short_hash}"
            )

    @property
    def fernet(self) -> Fernet:
        """
        Retrieves the Fernet encryption instance.

        :return: The Fernet instance used for encryption and decryption.
        """
        if self._fernet:
            # Check if the fernet key is different from the current encryption key.
            if self._fernet.current_key != self.key:
                # If they differ, reinitialize the Fernet object with the correct key.
                self._fernet = Fernet(self.key)
        else:
            self._fernet = Fernet(self.key)

        self._fernet.current_key = self.key

        return self._fernet

    @property
    def key(self) -> bytes:
        """
        Retrieves the encryption key used for secure phrase management.

        :return: The encryption key as a byte string, loaded from the key file.
        """
        if not self._is_key_in_json(self.KEY_FILE):
            self._generate_key()

        key_phrase = self._json_get_value(self.KEY_FILE)

        try:
            # Attempt to decrypt the key phrase using the master password's Fernet instance.
            key_phrase = self._mp_fernet.decrypt(
                key_phrase.encode(encoding="utf-8")
            )
        except (InvalidToken, InvalidSignature):
            # Raise a custom error if decryption fails due to an incorrect master password.
            raise SecurityInvalidPasswordError("Wrong master password!")

        return key_phrase

    def _save_master_password(self, key: str) -> None:
        """
        Saves the master password to a secure file after decoding it from a Base64 string.
        This method decodes the provided Base64-encoded master password and writes it
        to a designated file for secure storage.

        :param key: The Base64-encoded master password to be saved.
        """
        key = base64.urlsafe_b64decode(key)
        with open(self.MASTER_PASSWORD_FILE, "wb") as key_file:
            key_file.write(key)

    @staticmethod
    def _validate_master_password(password: str) -> str:
        """
        Validates the master password by ensuring it meets certain criteria:
        - Must be at least 4 characters long.
        - Cannot contain the underscore (_) character.
        - The length must be a multiple of 4.
          If it's not, the password is padded with underscores (_) until it
          becomes a multiple of 4.

        :param password: The master password to be validated.
        :return: The validated password, padded with underscores if necessary.
        :raises EnvironmentError: If the password is too short (less than 4
                                  characters) or contains an underscore (_).
        """
        # Check if the password is at least 4 characters long
        if len(password) < 4:
            raise SecurityInvalidPasswordError(
                "Your password needs to be at least 4 characters long."
            )

        # Check if the password contains an underscore, which is not allowed
        if "_" in password:
            raise SecurityInvalidPasswordError(
                "The password cannot contain the underscore (_) character."
            )

        # Check if the password length is already a multiple of 4
        pass_len = len(password) % 4
        if pass_len == 0:
            return password

        # Calculating the missing characters and padding with the "_" symbol
        padding = 4 - pass_len

        return f"{password}{'_' * padding}"

    def _open_master_password(self) -> bytes:
        """
        Handles the retrieval or creation of the master password,
        ensuring secure access:

        - If the master password file does not exist, the user is prompted to
          enter a secure master password, which is validated and
          optionally saved for future use.
        - If a skip file exists, the prompt for saving the master password is skipped.
        - If the master password file already exists, it is loaded, decoded,
          and used to generate a SHA-256 hash.

        :return: A SHA-256 hash of the master password,
                 used as a key for further cryptographic operations.
        """
        if not os.path.exists(self.MASTER_PASSWORD_FILE):
            master_password = self._get_secure_phrase("Enter master password")
            master_password = self._validate_master_password(master_password)

            if not os.path.exists(self.MASTER_PASSWORD_FILE_SKIP):
                question_save = self._question_for_save(
                    message="Save master password?\n"
                    "If You save it, the master key will be automatically "
                    "loaded next time. ( [Y]es / [N]o ):"
                )
                if question_save:
                    self._save_master_password(master_password)
                else:
                    skip_file_content = (
                        "If this file exists, the question for saving the "
                        "master password will be skipped.".encode("utf-8")
                    )
                    with open(
                        self.MASTER_PASSWORD_FILE_SKIP, "wb"
                    ) as skip_file:
                        skip_file.write(skip_file_content)
            master_password = master_password.replace("_", "")
        else:
            with open(self.MASTER_PASSWORD_FILE, "rb") as master_file:
                encoded_master_password = master_file.read()

            master_password = base64.urlsafe_b64encode(encoded_master_password)
            master_password = master_password.replace(b"_", b"")
            master_password = master_password.decode("utf-8")

        key_hash = hashlib.sha256(master_password.encode()).digest()

        return key_hash

    def master_key_veryfication(self):
        """todo"""
        pass

    @staticmethod
    def _generate_short_hash(data: str) -> str:
        """
        Generates a truncated SHA-256 hash of the provided data.

        :param data: The input data to be hashed, provided as a UTF-8 string.
        :return: The first 6 characters of the SHA-256 hash of the input data, as a hexadecimal string.
        """
        max_chars = 6
        sha256_hash = hashlib.sha256()
        sha256_hash.update(data.encode("utf-8"))

        # eg. returns 9f86d0 instead of 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
        return sha256_hash.hexdigest()[:max_chars]

    def _generate_key(self) -> None:
        """Generates a new encryption key and saves it to a json."""
        key = Fernet.generate_key()
        key = self._mp_fernet.encrypt(key)
        self._json_update(data={self.KEY_FILE: key.decode("utf-8")})

    def _is_key_in_json(self, key) -> bool:
        """
        Check if the specified key exists in the JSON file.

        :param key: The key to check for existence in the JSON file.
        :return: True if the key exists, False otherwise.
        """
        return bool(self._json_get_value(key))

    def manage_phrase(
        self, overwrite_phrase: bool = True, message: str = None
    ) -> str:
        """
        Manages the secure phrase by checking if an encrypted secure phrase file exists,
        and either retrieves, updates, or saves a new secure phrase based on user input.

        :param overwrite_phrase: If True, prompts the user to decide whether to overwrite
                                 the existing secure phrase.
        :param message: An optional message to display to the user before inputting the secure phrase.
        :return: The retrieved or newly generated secure phrase.
        """
        if self._is_key_in_json(self.ENCRYPTED_SECURE_PHRASE_FILE):
            if overwrite_phrase:
                question_overwrite = self._question_for_overwrite()
            else:
                question_overwrite = False

            saved_secure_phrase = self._open_secure_phrase()

            if question_overwrite:
                secure_phrase = self._get_secure_phrase(message)
                question_save = self._question_for_save()

                if question_save:
                    self._save_secure_phrase(secure_phrase)
                else:
                    # remove from json because we don't want to store these values anymore
                    self._json_delete_keys(
                        [self.ENCRYPTED_SECURE_PHRASE_FILE, self.KEY_FILE]
                    )
            else:
                secure_phrase = self._decode_secure_phrase(saved_secure_phrase)
        else:
            secure_phrase = self._get_secure_phrase(message)
            question_save = self._question_for_save()

            if question_save:
                self._save_secure_phrase(secure_phrase)

        return secure_phrase

    @staticmethod
    def _question_for_save(message: str = None) -> bool:
        """
        Prompts the user to confirm whether they want to save the secure phrase.

        :param message: The message to display to the user.
        :return: True if the user confirms saving by entering 'Y' or 'y', False otherwise.
        """
        if message is None:
            msg = "Save secure phrase? ( [Y]es / [N]o ): "
        else:
            msg = f"{message}"

        question = input(msg)
        return True if question.lower() == "y" else False

    @staticmethod
    def _question_for_overwrite() -> bool:
        """
        Prompts the user to confirm whether they want to overwrite the existing secure phrase.

        :return: True if the user confirms overwriting by entering 'Y' or 'y', False otherwise.
        """
        question = input("Overwrite secure phrase ? ( [Y]es / [N]o ): ")
        return True if question.lower() == "y" else False

    def _decode_secure_phrase(self, secure_phrase_to_decode: bytes) -> str:
        """
        Decodes and decrypts the provided secure phrase.

        :param secure_phrase_to_decode: The encrypted secure phrase in bytes format to be decoded.
        :return: The decrypted secure phrase as a UTF-8 string.
        """
        try:
            decrypted_data = self.fernet.decrypt(secure_phrase_to_decode)
        except (InvalidToken, InvalidSignature):
            raise SecurityInvalidPasswordError("Wrong master password!")

        return decrypted_data.decode("utf-8")

    def _encode_secure_phrase(self, secure_phrase_to_encode: str) -> bytes:
        """
        Encrypts and encodes the provided secure phrase.

        :param secure_phrase_to_encode: The secure phrase as a UTF-8 string that needs to be encrypted.
        :return: The encrypted secure phrase as a bytes object.
        """
        encoded_data = self.fernet.encrypt(
            bytes(secure_phrase_to_encode, encoding="utf-8")
        )
        return encoded_data

    def _open_secure_phrase(self) -> bytes:
        """
        Reads the encrypted secure phrase from the JSON file.

        :return: The encrypted secure phrase.
        """
        encrypted_secure_phrase = self._json_get_value(
            self.ENCRYPTED_SECURE_PHRASE_FILE
        )

        return encrypted_secure_phrase.encode(encoding="utf-8")

    def _save_secure_phrase(self, secure_phrase: str) -> None:
        """
        Encrypts and saves the secure phrase to a JSON file.

        :param secure_phrase: The secure phrase to be encrypted and saved as a UTF-8 string.
        """
        phrase = self._encode_secure_phrase(secure_phrase)

        if self._module_name:
            self._generate_key()
            phrase = self._encode_secure_phrase(secure_phrase)

        self._json_update(
            data={self.ENCRYPTED_SECURE_PHRASE_FILE: phrase.decode("utf-8")}
        )

    @staticmethod
    def _get_secure_phrase(message: str = None) -> str:
        """
        Prompts the user to enter a secure phrase and retrieves it.

        :param message: An optional message to display to the user before inputting the secure phrase.
        :return: The secure phrase entered by the user as a string.
        """
        default_message = (
            "Enter your secure phrase to save (eg. domain password/token):\n"
        )
        msg = f"{message}:\n" if message else default_message
        secure_phrase = getpass(prompt=msg)

        return secure_phrase

    def _json_save_data(self, data: dict[str, str]) -> None:
        """
        Save the given dictionary to the JSON file.
        This method writes the provided data to the specified file.
        If the file does not exist, it will be created.
        The data is written in a human-readable format with an indentation of 4 spaces.

        :param data: The dictionary containing data to be saved in JSON format.
        """
        with open(self.JSON_FILE, "w", encoding="utf-8") as json_file:
            json.dump(data, json_file, indent=4)

    def _json_load_data(self) -> dict[str, str]:
        """
        Load and return the data from the JSON file.
        This method reads specified JSON file and returns its contents
        as a dictionary. If the file does not exist,
        it returns an empty dictionary.

        :return: The contents of the JSON file as a dictionary.
                 If the file is not found, an empty dictionary is returned.
        """
        try:
            with open(self.JSON_FILE, "r") as json_file:
                data = json.load(json_file)
        except FileNotFoundError:
            data = {}

        return data

    def _json_get_value(self, key: str) -> str:
        """
        Retrieve the value associated with the given key from the JSON file.
        This method reads the data from the JSON file and attempts to return the value
        corresponding to the specified key. If the key is not found,
        it returns an empty byte string.

        :param key: The key whose associated value is to be retrieved from the JSON file.
        :return: The value associated with the key,
                 or an empty byte string if the key is not found.
        """
        try:
            json_key_data = self._json_load_data()[key]
        except KeyError:
            json_key_data = b""

        return json_key_data

    def _json_update(self, data: dict[str, str]) -> None:
        """
        Update the JSON file with the provided key-value pairs.
        This method reads the existing data from the JSON file,
        updates it with the new key-value pairs provided in the "data" param,
        and saves the updated data back to the JSON file.

        :param data: A dictionary containing the new key-value pairs to
                     update in the JSON file.
        """
        # Read the current JSON data from the file
        file_data = self._json_load_data()

        # Update the data with new key-value pairs
        file_data.update(data)

        # Write the updated data back to the JSON file
        self._json_save_data(file_data)

    def _json_delete_keys(self, key_list: list[str]) -> None:
        """
        Remove the specified keys from the JSON file.
        If a key is not found, it is ignored.

        :param key_list: A list of keys to be removed from the JSON file.
        """
        # Read the current JSON data from the file
        file_data = self._json_load_data()

        # Remove the keys from the JSON data
        for key in key_list:
            file_data.pop(key, None)

        # Write the updated data back to the JSON file
        self._json_save_data(file_data)


if __name__ == "__main__":
    s = Security()
    p = s.manage_phrase()
    print(p)
