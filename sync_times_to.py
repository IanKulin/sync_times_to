#!/usr/bin/env python3

import os
import subprocess  # for shell commands
import hashlib
import argparse
import shlex  # for quoting paths


def sync_file_times(local_dir, remote_machine, update_directory_flag):
    local_files = os.listdir(local_dir)

    for file_name in local_files:
        file_path = os.path.join(local_dir, file_name)
        quoted_file_path = shlex.quote(file_path)

        if not file_exists_on_remote(remote_machine, quoted_file_path):
            print(f"File {file_name} does not exist on the remote server")
            continue

        if not file_sizes_match(file_path, remote_machine, quoted_file_path):
            print(f"File sizes do not match for {file_name}")
            continue

        if file_times_match(file_path, remote_machine, quoted_file_path):
            print(f"File timestamp already matches for {file_name}")
            continue

        if not file_contents_match(file_path, remote_machine, quoted_file_path):
            print(f"File contents do not match for {file_name}")
            continue

        update_remote_file_timestamp(remote_machine, quoted_file_path, os.path.getmtime(file_path))
        print(f"Time updated for {file_name}")

    if update_directory_flag:
        # Update the timestamp of the parent directory
        local_dir_mtime = os.path.getmtime(local_dir)
        quoted_local_dir = shlex.quote(local_dir)
        update_remote_file_timestamp(remote_machine, quoted_local_dir, local_dir_mtime)
        print(f"Time updated for parent directory: {local_dir}")


def file_exists_on_remote(server_address, remote_file_path):
    command = f'ssh {server_address} "test -e {remote_file_path}"'
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0


def file_sizes_match(local_file_path, server_address, remote_file_path):
    local_size = os.path.getsize(local_file_path)
    remote_size = get_remote_file_size(server_address, remote_file_path)
    return local_size == remote_size


def file_times_match(local_file_path, server_address, remote_file_path):
    local_mtime = os.path.getmtime(local_file_path)
    remote_mtime = get_remote_file_mtime(server_address, remote_file_path)
    return int(local_mtime) == remote_mtime


def file_contents_match(local_file_path, server_address, remote_file_path):
    local_hash = compute_local_file_hash(local_file_path)
    remote_hash = compute_remote_file_hash(server_address, remote_file_path)
    return local_hash == remote_hash


def get_remote_file_size(server_address, remote_file_path):
    command = f'ssh {server_address} "stat -c %s {remote_file_path}"'
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return int(result.stdout.decode().strip())
    else:
        raise Exception(f"Failed to get file size for {remote_file_path}: {result.stderr.decode().strip()}")


def get_remote_file_mtime(server_address, remote_file_path):
    command = f'ssh {server_address} "stat -c %Y {remote_file_path}"'
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return int(result.stdout.decode().strip())
    else:
        raise Exception(f"Failed to get file modification time for {remote_file_path}: {result.stderr.decode().strip()}")


def update_remote_file_timestamp(server_address, remote_file_path, mtime):
    command = f'ssh {server_address} "touch -d @{int(mtime)} {remote_file_path}"'
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
    command = f'ssh {server_address} "sha256sum {remote_file_path}"'
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return result.stdout.decode().split()[0]
    else:
        raise Exception(f"Failed to compute SHA-256 hash for {remote_file_path}: {result.stderr.decode().strip()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sync file timestamps between local and remote directories.")
    parser.add_argument("remote_machine", help="The remote machine address in the format 'user@hostname'")
    parser.add_argument("-d", "--update-directory", action="store_true", help="Update the timestamp of the parent directory")
    args = parser.parse_args()

    remote_machine = args.remote_machine
    local_directory = os.getcwd()

    sync_file_times(local_directory, remote_machine, args.update_directory)
