import sftps
import os


sftps.sftps_logger(level="debug")

client = sftps.FtpClient()

client.connect(host="127.0.0.1")

client.login(username="user", password="pass")

client.create_directory(path="test")

test_content = "Hello, this is a test file for FTP upload!"
test_file_path = "test_upload.txt"
with open(test_file_path, "w") as f:
    f.write(test_content)

client.upload_file(test_file_path, "test/test_upload.txt")

client.download_file(remote_path="test/test_upload.txt", local_path="test_upload_clone.txt")

s = client.list_details()
for file in s:
    print(file.name)
    print(str(file.get_type()))

os.remove(test_file_path)

client.remove_file("test/test_upload.txt")

client.remove_directory(path="test", recursive=True, force=True)

os.remove("test_upload_clone.txt")