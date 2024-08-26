#!/usr/bin/env python3

import os
import subprocess
import hashlib
import argparse


# Function to check file sizes and update timestamps
def sync_files(local_dir, remote_machine):
    # List all files in the local directory
    local_files = os.listdir(local_dir)

    for file_name in local_files:
        file_path = os.path.join(local_dir, file_name)

        # Check if the file exists on the remote server
        if file_exists_on_remote(remote_machine, file_path):
            # Get the size of the local and remote files
            local_size = os.path.getsize(file_path)
            remote_size = get_remote_file_size(remote_machine, file_path)

            if local_size == remote_size:
                # Compute the SHA-256 hash of the local and remote files
                local_hash = compute_local_file_hash(file_path)
                remote_hash = compute_remote_file_hash(remote_machine, file_path)

                if local_hash == remote_hash:
                    # Get the local file's modification time
                    local_mtime = os.path.getmtime(file_path)
                    # Update the remote file's timestamp
                    update_remote_file_timestamp(remote_machine, file_path, local_mtime)
                    print(f"Time updated for {file_name}")
                else:
                    print(f"File contents do not match for {file_name}")
            else:
                print(f"File sizes do not match for {file_name}")
        else:
            print(f"File {file_name} does not exist on the remote server")


def file_exists_on_remote(server_address, remote_file_path):
    command = f"ssh {server_address} 'test -e {remote_file_path}'"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0


def get_remote_file_size(server_address, remote_file_path):
    command = f"ssh {server_address} 'stat -c %s {remote_file_path}'"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return int(result.stdout.decode().strip())
    else:
        raise Exception(f"Failed to get file size for {remote_file_path}: {result.stderr.decode().strip()}")


def update_remote_file_timestamp(server_address, remote_file_path, mtime):
    command = f"ssh {server_address} 'touch -d @{int(mtime)} {remote_file_path}'"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise Exception(f"Failed to update timestamp for {remote_file_path}: {result.stderr.decode().strip()}")


def compute_local_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def compute_remote_file_hash(server_address, remote_file_path):
    command = f"ssh {server_address} 'sha256sum {remote_file_path}'"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return result.stdout.decode().split()[0]
    else:
        raise Exception(f"Failed to compute SHA-256 hash for {remote_file_path}: {result.stderr.decode().strip()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sync file timestamps between local and remote directories.")
    parser.add_argument("remote_machine", help="The remote machine address in the format 'user@hostname'")
    args = parser.parse_args()

    remote_machine = args.remote_machine
    local_directory = os.getcwd()

    sync_files(local_directory, remote_machine)
