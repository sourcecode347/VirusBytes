# VirusBytesCLI.py
# Author: sourcecode347
import hashlib
import os
import sqlite3
import logging
import time
import requests
import argparse
import sys
import gc
import concurrent.futures
import threading
import pickle

# Configure logging to console
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Get script directory for absolute paths
script_dir = os.path.dirname(os.path.abspath(__file__))

global logoascii
logoascii = '''
░██    ░█░██                        ░████████             ░██                     
░██    ░██                          ░██    ░██            ░██                     
░██    ░█░█░██░███░██    ░██░███████░██    ░██░██    ░█░███████░███████ ░███████  
░██    ░█░█░███   ░██    ░█░██      ░████████ ░██    ░██  ░██ ░██    ░█░██        
 ░██  ░██░█░██    ░██    ░██░███████░██     ░█░██    ░██  ░██ ░█████████░███████  
  ░██░██ ░█░██    ░██   ░███      ░█░██     ░█░██   ░███  ░██ ░██             ░██ 
   ░███  ░█░██     ░█████░██░███████░█████████ ░█████░██   ░███░███████ ░███████  
                                                     ░██                          
                                               ░███████                           
'''
class VirusBytesCLI:
    def __init__(self):
        self.db_hashes = os.path.join(script_dir, "virus_hashes.db")
        self.quarantine_dir = os.path.join(script_dir, "quarantine")
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)
        self.quarantine_metadata_pkl = os.path.join(script_dir, "metadata.pkl")
        self.quarantine_metadata = self.load_quarantine_metadata()
        self.hashes_lock = threading.Lock()

        # Initialize database
        with self.get_hashes_connection() as conn:
            cur = conn.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS hashes (hash TEXT PRIMARY KEY)")
            conn.commit()

    def load_quarantine_metadata(self):
        if os.path.exists(self.quarantine_metadata_pkl):
            try:
                with open(self.quarantine_metadata_pkl, 'rb') as f:
                    return pickle.load(f)
            except Exception as e:
                logging.error(f"Failed to load quarantine metadata: {str(e)}")
                return {}
        return {}

    def save_quarantine_metadata(self):
        try:
            with open(self.quarantine_metadata_pkl, 'wb') as f:
                pickle.dump(self.quarantine_metadata, f)
        except Exception as e:
            logging.error(f"Failed to save quarantine metadata: {str(e)}")

    def get_hashes_connection(self):
        """Create a new SQLite connection for the hashes database."""
        conn = sqlite3.connect(self.db_hashes)
        conn.execute("PRAGMA synchronous = 0")
        conn.execute("PRAGMA journal_mode = MEMORY")
        return conn

    def compute_hash(self, file_path):
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(4096):
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)
            hashes = {
                'md5': md5_hash.hexdigest().lower(),
                'sha1': sha1_hash.hexdigest().lower(),
                'sha256': sha256_hash.hexdigest().lower()
            }
            logging.debug(f"Computed hashes for {file_path}: MD5={hashes['md5']}, SHA1={hashes['sha1']}, SHA256={hashes['sha256']}")
            return hashes
        except Exception as e:
            logging.error(f"Failed to compute hashes for {file_path}: {str(e)}")
            return None

    def scan_folder(self, folder, delete=False, quarantine=False, output=None):
        detected = []
        file_list = []
        for root_dir, _, files in os.walk(folder):
            for file in files:
                fp = os.path.join(root_dir, file)
                if not fp.endswith('.quarantine'):
                    file_list.append(fp)

        total_files = len(file_list)
        if total_files == 0:
            logging.info("No files found!")
            return

        logging.info(f"Scanning {total_files} files in {folder}")
        processed = 0
        lock = threading.Lock()

        def process_file(file_path):
            nonlocal processed
            if not os.path.isfile(file_path):
                logging.debug(f"Skipped non-regular file: {file_path}")
                with lock:
                    processed += 1
                    if processed % 100 == 0:
                        logging.info(f"Processed {processed}/{total_files} files")
                return
            size = os.path.getsize(file_path)
            if size < 1024:
                fsize = f"{size} bytes"
            elif size < pow(1024,2):
                fsize = f"{round(size/1024, 2)} KB"
            elif size < pow(1024,3):
                fsize = f"{round(size/(pow(1024,2)), 2)} MB"
            elif size < pow(1024,4):
                fsize = f"{round(size/(pow(1024,3)), 2)} GB"
            logging.info(f"Starting scan of {file_path} , size : {fsize}")
            if int(size)!=0:
                hashes = self.compute_hash(file_path)
                if hashes:
                    conn = self.get_hashes_connection()
                    try:
                        cur = conn.cursor()
                        try:
                            for hash_type, hash_val in hashes.items():
                                cur.execute("SELECT 1 FROM hashes WHERE hash = ?", (hash_val,))
                                if cur.fetchone():
                                    logging.info(f"Detected virus in {file_path}: {hash_type.upper()}={hash_val}")
                                    with lock:
                                        detected.append((file_path, hash_val))
                                    if delete:
                                        try:
                                            os.remove(file_path)
                                            logging.info(f"Deleted: {file_path}")
                                        except Exception as e:
                                            logging.error(f"Failed to delete {file_path}: {str(e)}")
                                    elif quarantine:
                                        self.quarantine_file(file_path, hash_val)
                                    break
                        finally:
                            cur.close()
                    finally:
                        conn.close()
            with lock:
                processed += 1
                if processed % 100 == 0:
                    logging.info(f"Processed {processed}/{total_files} files")

        max_workers = max(1, os.cpu_count() // 2)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(process_file, fp) for fp in file_list]
            concurrent.futures.wait(futures)

        logging.info("Scan completed")
        if detected:
            logging.info(f"Found {len(detected)} suspicious files.")
            for fp, fh in detected:
                logging.info(f"Detection: {fp} (Hash: {fh})")
            if output:
                try:
                    with open(output, 'w', encoding='utf-8') as f:
                        for fp, fh in detected:
                            f.write(f"Detection: {fp} (Hash: {fh})\n")
                    logging.info(f"Saved detections to {output}")
                except Exception as e:
                    logging.error(f"Failed to save detections to {output}: {str(e)}")
        else:
            logging.info("No viruses found!")
        gc.collect()

    def quarantine_file(self, file_path, file_hash):
        try:
            if file_path.endswith('.quarantine'):
                logging.warning(f"Skipped already quarantined file: {file_path}")
                return
            quarantine_filename = os.path.basename(file_path) + f".{file_hash}.quarantine"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            if os.path.exists(quarantine_path):
                os.remove(file_path)
                logging.info(f"Duplicate threat detected, deleted {file_path}")
                return
            try:
                os.rename(file_path, quarantine_path)
                self.quarantine_metadata[quarantine_filename] = file_path
                self.save_quarantine_metadata()
                logging.info(f"Quarantined: {file_path} to {quarantine_path}")
            except Exception as e:
                logging.error(f"Failed to quarantine {file_path}: {str(e)}")
                try:
                    os.remove(file_path)
                    logging.info(f"Deleted {file_path} due to quarantine failure")
                except Exception as de:
                    logging.error(f"Failed to delete {file_path}: {str(de)}")
        except Exception as e:
            logging.error(f"Failed to quarantine {file_path}: {str(e)}")

    def view_quarantine(self):
        files = [f for f in os.listdir(self.quarantine_dir) if f.endswith(".quarantine")]
        if not files:
            logging.info("Quarantine is empty.")
            return

        for file in files:
            quarantine_path = os.path.join(self.quarantine_dir, file)
            original_path = self.quarantine_metadata.get(file, os.path.join(os.path.dirname(quarantine_path), file.rsplit(".", 2)[0]))
            logging.info(f"Quarantined file: {quarantine_path} (Original: {original_path})")
            action = input("Action (delete/restore/ignore): ").strip().lower()
            if action == "delete":
                try:
                    os.remove(quarantine_path)
                    if file in self.quarantine_metadata:
                        del self.quarantine_metadata[file]
                        self.save_quarantine_metadata()
                    logging.info(f"Deleted: {quarantine_path}")
                except Exception as e:
                    logging.error(f"Failed to delete {quarantine_path}: {str(e)}")
            elif action == "restore":
                try:
                    os.rename(quarantine_path, original_path)
                    if file in self.quarantine_metadata:
                        del self.quarantine_metadata[file]
                        self.save_quarantine_metadata()
                    logging.info(f"Restored: {quarantine_path} to {original_path}")
                except Exception as e:
                    logging.error(f"Failed to restore {quarantine_path}: {str(e)}")
            elif action == "ignore":
                logging.info(f"Ignored: {quarantine_path}")
            else:
                logging.warning("Invalid action, skipping.")

    def update_db(self):
        url = "https://www.virusbytes.com/virus_hashes.db"
        try:
            logging.info(f"Downloading database from {url}...")
            response = requests.get(url, stream=True)
            response.raise_for_status()
            total_size = int(response.headers.get('content-length', 0))
            block_size = 1024
            downloaded = 0
            with open(self.db_hashes, 'wb') as f:
                for data in response.iter_content(block_size):
                    downloaded += len(data)
                    f.write(data)
                    if total_size > 0:
                        progress = (downloaded / total_size) * 100
                        logging.info(f"Download progress: {progress:.2f}%")
            logging.info("Database updated successfully.")
            with self.get_hashes_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM hashes")
                count = cur.fetchone()[0]
                logging.info(f"Loaded {count} hashes.")
        except Exception as e:
            logging.error(f"Failed to update database: {str(e)}")

    def remove_false_positives(self, fp_file):
        if not os.path.exists(fp_file):
            logging.error(f"File not found: {fp_file}")
            return

        removed_count = 0
        with open(fp_file, 'r', encoding='utf-8') as f:
            hashes_to_remove = [line.strip().lower() for line in f if line.strip()]

        if not hashes_to_remove:
            logging.info("No hashes found in the file.")
            return

        conn = self.get_hashes_connection()
        try:
            cur = conn.cursor()
            for hash_val in hashes_to_remove:
                cur.execute("DELETE FROM hashes WHERE hash = ?", (hash_val,))
                if cur.rowcount > 0:
                    logging.info(f"Removed hash: {hash_val}")
                    removed_count += 1
                else:
                    logging.warning(f"Hash not found in database: {hash_val}")
            conn.commit()
        except Exception as e:
            logging.error(f"Failed to remove hashes: {str(e)}")
        finally:
            cur.close()
            conn.close()

        logging.info(f"Removed {removed_count} hashes from the database.")

    def import_hashes(self, hash_file):
        if not os.path.exists(hash_file):
            logging.error(f"File not found: {hash_file}")
            return

        added_count = 0
        skipped_count = 0
        with open(hash_file, 'r', encoding='utf-8') as f:
            hashes_to_add = [line.strip().lower() for line in f if line.strip()]

        if not hashes_to_add:
            logging.info("No hashes found in the file.")
            return

        conn = self.get_hashes_connection()
        try:
            cur = conn.cursor()
            for hash_val in hashes_to_add:
                if self.is_valid_hash(hash_val):
                    cur.execute("INSERT OR IGNORE INTO hashes (hash) VALUES (?)", (hash_val,))
                    if cur.rowcount > 0:
                        logging.info(f"Added hash: {hash_val}")
                        added_count += 1
                    else:
                        logging.info(f"Hash already exists: {hash_val}")
                else:
                    logging.warning(f"Invalid hash (not MD5, SHA1, or SHA256): {hash_val}")
                    skipped_count += 1
            conn.commit()
        except Exception as e:
            logging.error(f"Failed to import hashes: {str(e)}")
        finally:
            cur.close()
            conn.close()

        logging.info(f"Added {added_count} hashes to the database. Skipped {skipped_count} invalid hashes.")

    def is_valid_hash(self, hash_val):
        length = len(hash_val)
        if length not in (32, 40, 64):
            return False
        try:
            int(hash_val, 16)
            return True
        except ValueError:
            return False

    def info_db(self):
        conn = self.get_hashes_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM hashes")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM hashes WHERE LENGTH(hash) = 32")
        md5_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM hashes WHERE LENGTH(hash) = 40")
        sha1_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM hashes WHERE LENGTH(hash) = 64")
        sha256_count = cur.fetchone()[0]
        cur.close()
        conn.close()

        if os.path.exists(self.db_hashes):
            db_size = os.path.getsize(self.db_hashes)
            if db_size < 1024:
                size_str = f"{db_size} bytes"
            elif db_size < 1024**2:
                size_str = f"{round(db_size / 1024, 2)} KB"
            elif db_size < 1024**3:
                size_str = f"{round(db_size / (1024**2), 2)} MB"
            else:
                size_str = f"{round(db_size / (1024**3), 2)} GB"
        else:
            size_str = "0 bytes"

        logging.info(f"Total hashes : {total}")
        logging.info(f"MD5 hashes   : {md5_count}")
        logging.info(f"SHA1 hashes  : {sha1_count}")
        logging.info(f"SHA256 hashes: {sha256_count}")
        logging.info(f"Database size: {size_str}")

    def export_hashes(self, export_file, hash_type='all'):
        if hash_type not in ['all', 'md5', 'sha1', 'sha256']:
            logging.error(f"Invalid hash type: {hash_type}. Must be one of: all, md5, sha1, sha256")
            return

        conn = self.get_hashes_connection()
        cur = conn.cursor()

        if hash_type == 'all':
            cur.execute("SELECT hash FROM hashes")
        elif hash_type == 'md5':
            cur.execute("SELECT hash FROM hashes WHERE LENGTH(hash) = 32")
        elif hash_type == 'sha1':
            cur.execute("SELECT hash FROM hashes WHERE LENGTH(hash) = 40")
        elif hash_type == 'sha256':
            cur.execute("SELECT hash FROM hashes WHERE LENGTH(hash) = 64")

        hashes = cur.fetchall()
        cur.close()
        conn.close()

        exported_count = len(hashes)
        try:
            with open(export_file, 'w', encoding='utf-8') as f:
                for h in hashes:
                    f.write(f"{h[0]}\n")
            logging.info(f"Exported {exported_count} hashes to {export_file}")
        except Exception as e:
            logging.error(f"Failed to export hashes to {export_file}: {str(e)}")
def donation():
    print("Please Make a Donation to Support This Open Source Project : \n  https://buy.stripe.com/fZu28keQj5Um1Yk6P01gs00")

def print_custom_help():
    print("VirusBytesCLI.py - Cross Platform Open Source Antivirus")
    print()
    print("Usage: python3 VirusBytesCLI.py [options]")
    print()
    print("+-----------------------------------+------------------------------------------------------------+")
    print("| Command                           | Description                                                |")
    print("+-----------------------------------+------------------------------------------------------------+")
    print("| --updatedb                        | Update the virus hashes database from                      |")
    print("|                                   | https://www.virusbytes.com/virus_hashes.db. Shows download |")
    print("|                                   | progress in console.                                       |")
    print("+-----------------------------------+------------------------------------------------------------+")
    print("| --scan --path <path>              | Scan the specified path and log detections to console.     |")
    print("| [--output <file>]                 | Optionally save detections to the specified file.          |")
    print("|                                   | If no --delete or --quarantine, only logs without action.  |")
    print("+-----------------------------------+------------------------------------------------------------+")
    print("| --scan --path <path> --delete     | Scan the path, delete detections immediately, log to       |")
    print("| [--output <file>]                 | console. Optionally save to file.                          |")
    print("+-----------------------------------+------------------------------------------------------------+")
    print("| --scan --path <path> --quarantine | Scan the path, quarantine detections, log full paths to    |")
    print("| [--output <file>]                 | console. Optionally save to file.                          |")
    print("+-----------------------------------+------------------------------------------------------------+")
    print("| --view --quarantine               | View quarantined files one by one with options: delete,    |")
    print("|                                   | restore, ignore. Interactive mode in console.              |")
    print("+-----------------------------------+------------------------------------------------------------+")
    print("| --remove <file>                   | Remove false positive hashes from the database listed in   |")
    print("|                                   | the specified file (one hash per line).                    |")
    print("+-----------------------------------+------------------------------------------------------------+")
    print("| --import <file>                   | Import known virus hashes (MD5, SHA1, SHA256) from the     |")
    print("|                                   | specified file (one hash per line) into the database.      |")
    print("+-----------------------------------+------------------------------------------------------------+")
    print("| --infodb                          | Display information about the virus hashes database: total |")
    print("|                                   | hashes, MD5 count, SHA1 count, SHA256 count, and size.     |")
    print("+-----------------------------------+------------------------------------------------------------+")
    print("| --export <file> --type <type>     | Export hashes from the database to the specified file.     |")
    print("|                                   | Type can be all, md5, sha1, sha256.                        |")
    print("+-----------------------------------+------------------------------------------------------------+")
    print("| --help                            | Show this help message and exit.                           |")
    print("+-----------------------------------+------------------------------------------------------------+")
    donation()
    sys.exit(0)

if __name__ == "__main__":
    print(logoascii)
    if '--help' in sys.argv:
        print_custom_help()

    parser = argparse.ArgumentParser(description="VirusBytes Server", add_help=False)
    parser.add_argument('--scan', action='store_true', help='Scan mode')
    parser.add_argument('--path', type=str, help='Path to scan')
    parser.add_argument('--delete', action='store_true', help='Delete detections')
    parser.add_argument('--quarantine', action='store_true', help='Quarantine detections')
    parser.add_argument('--output', type=str, help='Output file for detections')
    parser.add_argument('--view', action='store_true', help='View quarantine')
    parser.add_argument('--updatedb', action='store_true', help='Update database')
    parser.add_argument('--remove', type=str, help='File containing false positive hashes to remove')
    parser.add_argument('--import', dest='import_hashes', type=str, help='File containing virus hashes to import')
    parser.add_argument('--infodb', action='store_true', help='Display database info')
    parser.add_argument('--export', type=str, help='File to export hashes to')
    parser.add_argument('--type', type=str, default='all', help='Type of hashes to export: all, md5, sha1, sha256')

    args = parser.parse_args()

    app = VirusBytesCLI()

    if args.updatedb:
        app.update_db()
        donation()
    elif args.scan and args.path:
        if args.delete and args.quarantine:
            logging.error("Cannot use --delete and --quarantine together.")
            donation()
            sys.exit(1)
        app.scan_folder(args.path, delete=args.delete, quarantine=args.quarantine, output=args.output)
        donation()
    elif args.view and args.quarantine:
        app.view_quarantine()
        donation()
    elif args.remove:
        app.remove_false_positives(args.remove)
        donation()
    elif args.import_hashes:
        app.import_hashes(args.import_hashes)
        donation()
    elif args.infodb:
        app.info_db()
        donation()
    elif args.export:
        app.export_hashes(args.export, args.type)
        donation()
    else:
        print_custom_help()