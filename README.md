# SFTPS

A Python FTP package implemented in Rust.

## Project Description

SFTPS is a high-performance FTP client library with core functionality implemented in Rust and an easy-to-use Python API. This library aims to provide fast and reliable FTP file transfer capabilities.

## Installation

```bash
pip install sftps
```

## Usage

```python
import sftps
import os

# Set up core code with debug level log
sftps.sftps_logger(level="debug")


# Create ftp client instance
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
```

## Features

- High Performance: Core functionality implemented in Rust
- Ease of Use: Clean Python API
- Security: TLS/SSL encryption support
- Reliability: Automatic reconnection and error handling

## Todo

- [ ] Auto create not exist remove directory
- [ ] FTPS
- [ ] SFTP
- [ ] Recursive or force delete directory
- [ ] Resume file upload or download
- [ ] Async FTP
- [ ] Benchmark test
