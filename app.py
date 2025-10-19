import os
import struct
import threading
from pathlib import Path

import customtkinter as ctk
from tkinter import filedialog, messagebox

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# -------------------- Crypto core --------------------
MAGIC = b"FET1"
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
NAME_LEN_FMT = "<H"  # unsigned short
CHUNK_SIZE = 1024 * 1024  # 1 MiB
PBKDF2_ITER = 200_000
KEY_LEN = 32  # AES-256

backend = default_backend()


def _derive_key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str) or password == "":
        raise ValueError("Password must be a non-empty string.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITER,
        backend=backend,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(in_path: Path, out_path: Path, password: str, progress_cb=None, stop_flag=None):
    import secrets

    in_path = Path(in_path)
    out_path = Path(out_path)

    if not in_path.exists() or not in_path.is_file():
        raise FileNotFoundError("Input file not found")

    file_size = in_path.stat().st_size

    salt = secrets.token_bytes(SALT_LEN)
    key = _derive_key(password, salt)
    nonce = secrets.token_bytes(NONCE_LEN)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend)
    encryptor = cipher.encryptor()

    original_name = in_path.name.encode("utf-8")
    name_len = len(original_name)

    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        # Write header (without tag)
        fout.write(MAGIC)
        fout.write(salt)
        fout.write(nonce)
        fout.write(struct.pack(NAME_LEN_FMT, name_len))
        fout.write(original_name)

        processed = 0
        while True:
            if stop_flag and stop_flag.is_set():
                raise RuntimeError("Encryption cancelled by user")
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            ct = encryptor.update(chunk)
            if ct:
                fout.write(ct)
            processed += len(chunk)
            if progress_cb:
                progress_cb(processed / file_size if file_size else 1.0)

        encryptor.finalize()
        tag = encryptor.tag
        # Append tag at the end
        fout.write(tag)


def decrypt_file(in_path: Path, out_dir: Path, password: str, progress_cb=None, stop_flag=None) -> Path:
    in_path = Path(in_path)
    out_dir = Path(out_dir)
    if not in_path.exists() or not in_path.is_file():
        raise FileNotFoundError("Encrypted file not found")
    if in_path.stat().st_size < (4 + SALT_LEN + NONCE_LEN + 2 + TAG_LEN):
        raise ValueError("File too small or invalid format")

    total_size = in_path.stat().st_size

    with open(in_path, "rb") as fin:
        # Read header
        magic = fin.read(4)
        if magic != MAGIC:
            raise ValueError("Invalid file format (bad magic)")
        salt = fin.read(SALT_LEN)
        nonce = fin.read(NONCE_LEN)
        name_len = struct.unpack(NAME_LEN_FMT, fin.read(2))[0]
        original_name = fin.read(name_len).decode("utf-8", errors="replace")

        # Read tag from end
        fin.seek(-TAG_LEN, os.SEEK_END)
        tag = fin.read(TAG_LEN)

        # Ciphertext region is from current after header to EOF - TAG_LEN
        data_start = 4 + SALT_LEN + NONCE_LEN + 2 + name_len
        data_end = total_size - TAG_LEN
        data_len = data_end - data_start
        if data_len < 0:
            raise ValueError("Corrupted file (negative data length)")

        # Prepare decryptor
        key = _derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=backend)
        decryptor = cipher.decryptor()

        # Output path
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / original_name
        # Avoid overwrite silently
        counter = 1
        base = out_path.stem
        suffix = out_path.suffix
        while out_path.exists():
            out_path = out_dir / f"{base} (restored {counter}){suffix}"
            counter += 1

        with open(out_path, "wb") as fout:
            processed = 0
            fin.seek(data_start, os.SEEK_SET)
            remaining = data_len
            while remaining > 0:
                if stop_flag and stop_flag.is_set():
                    raise RuntimeError("Decryption cancelled by user")
                to_read = min(CHUNK_SIZE, remaining)
                chunk = fin.read(to_read)
                if not chunk:
                    break
                pt = decryptor.update(chunk)
                if pt:
                    fout.write(pt)
                processed += len(chunk)
                remaining -= len(chunk)
                if progress_cb:
                    progress_cb(processed / data_len if data_len else 1.0)
            decryptor.finalize()

    return out_path


# -------------------- UI --------------------
class FileEncryptionApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("File Encryption Tool — AES-256-GCM")
        self.geometry("780x520")
        ctk.set_appearance_mode("dark")  # default appearance
        ctk.set_default_color_theme("blue")

        self.selected_file = None
        self.output_dir = None

        self._build_ui()
        self._lock_ui(False)
        self.stop_event = threading.Event()

    # ---------- UI layout ----------
    def _build_ui(self):
        # Top bar
        top = ctk.CTkFrame(self, corner_radius=16)
        top.pack(fill="x", padx=16, pady=(16, 8))

        title = ctk.CTkLabel(top, text="File Encryption Tool", font=("Segoe UI", 22, "bold"))
        title.pack(side="left", padx=12, pady=12)

        self.mode_switch = ctk.CTkSwitch(top, text="Light Mode", command=self._toggle_mode)
        self.mode_switch.pack(side="right", padx=12)

        # File picker
        picker = ctk.CTkFrame(self, corner_radius=16)
        picker.pack(fill="x", padx=16, pady=8)

        self.file_entry = ctk.CTkEntry(picker, placeholder_text="No file selected", width=520)
        self.file_entry.pack(side="left", padx=(12, 8), pady=12)

        browse_btn = ctk.CTkButton(picker, text="Choose File", command=self._choose_file)
        browse_btn.pack(side="left", padx=(0, 12))

        out_btn = ctk.CTkButton(picker, text="Output Folder (optional)", command=self._choose_output)
        out_btn.pack(side="left", padx=(0, 12))

        # Password area
        pw_frame = ctk.CTkFrame(self, corner_radius=16)
        pw_frame.pack(fill="x", padx=16, pady=8)

        self.pw_entry = ctk.CTkEntry(pw_frame, placeholder_text="Enter strong passphrase…", show="*", width=520)
        self.pw_entry.pack(side="left", padx=(12, 8), pady=12)

        self.show_pw = ctk.CTkCheckBox(pw_frame, text="Show", command=self._toggle_pw)
        self.show_pw.pack(side="left", padx=(0, 12))

        # Buttons
        actions = ctk.CTkFrame(self, corner_radius=16)
        actions.pack(fill="x", padx=16, pady=8)

        self.encrypt_btn = ctk.CTkButton(actions, text="Encrypt", command=self._start_encrypt, width=140)
        self.encrypt_btn.pack(side="left", padx=12, pady=12)

        self.decrypt_btn = ctk.CTkButton(actions, text="Decrypt", command=self._start_decrypt, width=140)
        self.decrypt_btn.pack(side="left", padx=12, pady=12)

        self.cancel_btn = ctk.CTkButton(actions, text="Cancel", command=self._cancel_job, width=120, state="disabled")
        self.cancel_btn.pack(side="left", padx=12, pady=12)

        # Progress & status
        prog_wrap = ctk.CTkFrame(self, corner_radius=16)
        prog_wrap.pack(fill="x", padx=16, pady=8)

        self.progress = ctk.CTkProgressBar(prog_wrap)
        self.progress.set(0)
        self.progress.pack(fill="x", padx=12, pady=(16, 8))

        self.status = ctk.CTkTextbox(prog_wrap, height=160)
        self.status.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.status.insert("end", "Ready. Choose a file, set a passphrase, then Encrypt/Decrypt.\n")
        self.status.configure(state="disabled")

        # Footer tips
        tips = ctk.CTkLabel(self, text=(
            "Tip: Use a long passphrase (e.g., 4+ random words). Keep it safe — without it, files cannot be recovered."),
            wraplength=740)
        tips.pack(padx=16, pady=(0, 12))

    # ---------- Helpers ----------
    def _log(self, msg: str):
        self.status.configure(state="normal")
        self.status.insert("end", msg + "\n")
        self.status.see("end")
        self.status.configure(state="disabled")

    def _toggle_mode(self):
        if self.mode_switch.get():
            ctk.set_appearance_mode("light")
            self.mode_switch.configure(text="Dark Mode")
        else:
            ctk.set_appearance_mode("dark")
            self.mode_switch.configure(text="Light Mode")

    def _toggle_pw(self):
        self.pw_entry.configure(show="" if self.show_pw.get() else "*")

    def _choose_file(self):
        path = filedialog.askopenfilename(title="Choose a file to encrypt/decrypt")
        if path:
            self.selected_file = Path(path)
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, str(self.selected_file))

    def _choose_output(self):
        path = filedialog.askdirectory(title="Choose output folder")
        if path:
            self.output_dir = Path(path)
            self._log(f"Output folder set to: {self.output_dir}")

    def _progress_cb(self, value: float):
        # must run on UI thread; use after() to marshal
        self.after(0, lambda: self.progress.set(max(0.0, min(1.0, value))))

    def _lock_ui(self, working: bool):
        state = "disabled" if working else "normal"
        self.encrypt_btn.configure(state=state)
        self.decrypt_btn.configure(state=state)
        self.cancel_btn.configure(state="normal" if working else "disabled")
        self.file_entry.configure(state=state)
        self.pw_entry.configure(state=state)

    def _cancel_job(self):
        self.stop_event.set()
        self._log("Cancelling… (please wait)")

    def _validate_inputs(self, need_file=True, need_pw=True):
        if need_file and not self.selected_file:
            messagebox.showwarning("Missing file", "Please choose a file first.")
            return False
        pw = self.pw_entry.get()
        if need_pw and (not pw or len(pw) < 8):
            messagebox.showwarning("Weak password", "Use a passphrase of at least 8 characters (preferably longer).")
            return False
        return True

    # ---------- Encrypt/Decrypt flows ----------
    def _start_encrypt(self):
        if not self._validate_inputs():
            return
        in_path = self.selected_file
        out_path = (self.output_dir or in_path.parent) / (in_path.name + ".enc")
        password = self.pw_entry.get()

        def job():
            try:
                self._log(f"Encrypting: {in_path} → {out_path}")
                self.stop_event.clear()
                self._lock_ui(True)
                self.progress.set(0)
                encrypt_file(in_path, out_path, password, progress_cb=self._progress_cb, stop_flag=self.stop_event)
                self.after(0, lambda: self._log("Encryption complete."))
                self.after(0, lambda: messagebox.showinfo("Done", f"Encrypted to:\n{out_path}"))
            except RuntimeError as e:
                self.after(0, lambda: self._log(f"{e}"))
            except Exception as e:
                self.after(0, lambda: self._log(f"Error: {e}"))
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.after(0, lambda: self._lock_ui(False))
                self.stop_event.clear()

        threading.Thread(target=job, daemon=True).start()

    def _start_decrypt(self):
        if not self._validate_inputs():
            return
        in_path = self.selected_file
        if in_path.suffix.lower() != ".enc":
            if not messagebox.askyesno("Continue?", "Selected file does not end with .enc. Try to decrypt anyway?"):
                return
        out_dir = (self.output_dir or in_path.parent)
        password = self.pw_entry.get()

        def job():
            try:
                self._log(f"Decrypting: {in_path}")
                self.stop_event.clear()
                self._lock_ui(True)
                self.progress.set(0)
                restored = decrypt_file(in_path, out_dir, password, progress_cb=self._progress_cb, stop_flag=self.stop_event)
                self.after(0, lambda: self._log(f"Decryption complete: {restored}"))
                self.after(0, lambda: messagebox.showinfo("Done", f"Restored to:\n{restored}"))
            except RuntimeError as e:
                self.after(0, lambda: self._log(f"{e}"))
            except Exception as e:
                self.after(0, lambda: self._log(f"Error: {e}"))
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.after(0, lambda: self._lock_ui(False))
                self.stop_event.clear()

        threading.Thread(target=job, daemon=True).start()


if __name__ == "__main__":
    app = FileEncryptionApp()
    app.mainloop()
