"""
KIIBOT CLI Utama — Semua 26 Modul Terhubung ke Engine Backend.
"""

import asyncio
import sys

import click

from kiibot.cli.ctf_cli import ctf  # CTF Attack & Defense
from kiibot.utils import output

__version__ = "1.0.0"


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _run_async(coro):
    """Menjalankan coroutine async secara sinkron dari CLI."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            return asyncio.run(coro)
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


def _print_analysis_report(report) -> None:
    """Cetak AnalysisReport dengan format mendetail menggunakan Rich."""
    output.section(f"Laporan Analisis: {report.filename}")
    output.key_value("Path", report.path)
    output.key_value("Ukuran", f"{report.size:,} bytes")
    output.key_value("Tipe File", report.description)
    output.key_value("Kategori CTF", report.category.upper())
    output.key_value("Magic MIME", report.magic_type)
    output.section("Hash Kriptografi")
    output.key_value("MD5", report.md5)
    output.key_value("SHA-1", report.sha1)
    output.key_value("SHA-256", report.sha256)
    output.key_value("CRC32", report.crc32)
    output.section("Shannon Entropy")
    output.key_value("Entropy", f"{report.entropy:.4f} / 8.0")
    output.key_value("Keterangan", report.entropy_desc)

    if report.flags_found:
        output.section("FLAG DITEMUKAN")
        for flag in report.flags_found:
            output.success(flag)

    if report.checksec:
        c = report.checksec
        output.section("Checksec — Mitigasi Keamanan Biner")
        output.key_value("Arsitektur", f"{c.arch} ({c.bits}-bit, {c.endian} endian)")
        if c.nx is not None:
            output.key_value("NX / DEP", "[OK] Aktif" if c.nx else "[WARNING] Tidak Aktif")
        if c.pie is not None:
            output.key_value("PIE", "[OK] Aktif" if c.pie else "[WARNING] Tidak Aktif")
        if c.canary is not None:
            output.key_value("Stack Canary", "[OK] Aktif" if c.canary else "[WARNING] Tidak Aktif")
        output.key_value("RELRO", c.relro)
        if c.stripped is not None:
            output.key_value("Stripped", "Ya" if c.stripped else "Tidak (simbol debug tersedia)")

    if report.stego_indicators:
        output.section("Indikator Steganografi")
        for ind in report.stego_indicators:
            output.warning(ind)

    if report.embedded_files:
        output.section("File Tersembunyi / Embedded")
        for emb in report.embedded_files:
            output.info(emb)

    if report.strings_sample:
        output.section(f"String Diekstrak (sampel {len(report.strings_sample)} string)")
        for s in report.strings_sample[:15]:
            output.dim(f"  {s[:120]}")

    if report.recommended_tools:
        output.section("Rekomendasi Tools & Perintah Siap Pakai")
        rows = [[tool, cmd] for tool, cmd in report.recommended_tools]
        output.table(
            "Rekomendasi Tools",
            [("Tool", "bright_cyan"), ("Perintah", "bright_white")],
            rows,
            show_lines=True,
        )

def _check_and_install_missing_tools(tool_names: list[str]) -> None:
    """Memeriksa keberadaan tool eksternal, dan menawarkan auto-install jika tidak ada."""
    import shutil

    from kiibot.tools.installer import ToolInstaller
    missing = [t for t in tool_names if not shutil.which(t)]
    if not missing:
        return

    output.warning(f"Tool eksternal berikut tidak ditemukan di sistem: {', '.join(missing)}")
    if click.confirm("Apakah Anda ingin KIIBOT mencoba menginstallnya sekarang secara otomatis?"):
        installer = ToolInstaller()
        plan = installer.build_plan(tool_names=missing, only_missing=True)
        if not plan.is_empty():
            with output.status("Menginstall tools... (membutuhkan koneksi internet/sudo)"):
                # Menjalankan plan tanpa dry_run
                results = installer.execute_plan(plan, dry_run=False, progress_cb=lambda m: None)
            
            success = [cmd for cmd, ok in results.items() if ok]
            if success:
                output.success("Instalasi berhasil.")
            else:
                output.error("Gagal menginstall beberapa tool. KIIBOT akan menggunakan mode Native Fallback.")
        else:
            output.warning("Tidak ada instruksi instalasi untuk tool tersebut di registry.")
    else:
        output.info("Menggunakan mode Native Fallback.")


# ─── CLI Group ─────────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True, help="Tampilkan versi KIIBOT.")
@click.pass_context
def cli(ctx, version):
    """
    Intelligent Local CTF Toolkit.
    """
    if version:
        output.banner(f"KIIBOT v{__version__}", "Intelligent Local CTF Toolkit")
        sys.exit(0)

    if ctx.invoked_subcommand is None:
        from kiibot.core.constants import APP_BANNER, MAIN_MENU_ITEMS

        click.secho(APP_BANNER, fg="cyan", bold=True)

        while True:
            output.menu([(item[0], item[1]) for item in MAIN_MENU_ITEMS], "Pilih modul (ketik nomor, 00=Exit):")

            try:
                choice = click.prompt("Menu", type=str).strip()
            except (KeyboardInterrupt, EOFError):
                output.info("Keluar dari KIIBOT.")
                break

            if choice == "00":
                output.info("Keluar dari KIIBOT.")
                break

            selected = next((item for item in MAIN_MENU_ITEMS if item[0] == choice.zfill(2)), None)
            if not selected:
                output.error("Pilihan tidak valid. Ketik nomor yang ada di daftar menu.")
                continue

            cmd_name = selected[2]
            output.section(f"Modul Aktif: [{selected[0]}] {selected[1]}")

            try:
                _dispatch_menu(ctx, cmd_name, selected[1])
            except (KeyboardInterrupt, EOFError):
                output.warning("Dibatalkan oleh pengguna.")

            click.pause("\nTekan tombol apapun untuk kembali ke menu...")


def _dispatch_menu(ctx, cmd_name: str, label: str) -> None:
    """Memetakan perintah menu ke implementasi nyata."""
    if cmd_name == "exit":
        sys.exit(0)

    # ── Modul yang terhubung ke engine nyata ──────────────────────────────────
    elif cmd_name == "doctor":
        verbose = click.confirm("Tampilkan detail per kategori?", default=False)
        ctx.invoke(doctor, verbose=verbose)

    elif cmd_name == "workspace":
        ctx.invoke(workspace)

    elif cmd_name == "tools":
        ctx.invoke(tools)

    elif cmd_name == "solve":
        text = click.prompt("Masukkan teks / cipher / file path")
        ctx.invoke(solve, cipher=text)

    elif cmd_name == "analyze":
        path = click.prompt("Masukkan path file yang akan dianalisis")
        ctx.invoke(analyze, file_path=path)

    elif cmd_name == "crypto":
        text = click.prompt("Masukkan teks untuk didekode (Base64/Hex/ROT/XOR/dll.)")
        ctx.invoke(crypto, text=text)

    elif cmd_name == "hash":
        text = click.prompt("Masukkan string hash untuk diidentifikasi")
        ctx.invoke(hash_cmd, text=text)

    elif cmd_name == "steg":
        path = click.prompt("Masukkan path file gambar (PNG/JPEG/BMP)")
        ctx.invoke(steg, file_path=path)

    elif cmd_name == "pwn":
        action = click.prompt(
            "Pilih aksi (cyclic/find)",
            type=click.Choice(["cyclic", "find"]),
            default="cyclic",
        )
        if action == "cyclic":
            length = click.prompt("Panjang pattern", type=int, default=100)
            ctx.invoke(pwn, action="cyclic", value=str(length))
        else:
            val = click.prompt("Masukkan substring atau register hex (contoh: baaa atau 0x61616162)")
            ctx.invoke(pwn, action="find", value=val)

    elif cmd_name == "rsa":
        output.info("Serangan RSA CTF (Small-e & Wiener).")
        n = click.prompt("Modulus N", type=int)
        e = click.prompt("Exponent e", type=int)
        c = click.prompt("Ciphertext C", type=int)
        ctx.invoke(rsa, n=n, e=e, c=c)

    elif cmd_name in ("forensics", "pcap", "log"):
        path = click.prompt(f"Masukkan path file untuk analisis [{label}]")
        ctx.invoke(forensics, file_path=path)

    elif cmd_name == "flag":
        text = click.prompt("Masukkan teks / path direktori untuk pencarian flag")
        ctx.invoke(flag_hunt, target=text)

    elif cmd_name == "ctf":
        output.section("CTF Attack & Defense — Kucing Oyenn")
        output.info("Gunakan subcommand berikut dari terminal:")
        output.info("  kiibot ctf session start   — mulai session baru")
        output.info("  kiibot ctf session status  — status session aktif")
        output.info("  kiibot ctf target set <IP> — set target aktif")
        output.info("  kiibot ctf challenge add   — tambah challenge")
        output.info("  kiibot ctf attack log      — catat attack")
        output.info("  kiibot ctf defense log     — catat defense")
        output.info("  kiibot ctf finding add     — tambah finding")
        output.info("  kiibot ctf retest log      — catat retest")
        output.info("  kiibot ctf timeline        — lihat timeline")
        output.info("  kiibot ctf report          — generate laporan")
        output.info("  kiibot ctf summary         — ringkasan cepat")

    else:
        output.warning(
            f"Modul '{label}' ({cmd_name}) sedang dalam pengembangan dan akan tersedia di fase berikutnya."
        )


# Attach CTF subgroup ke CLI utama
cli.add_command(ctf)


# ─── Sub-Commands ──────────────────────────────────────────────────────────────

@cli.command()
@click.option("--verbose", is_flag=True, help="Tampilkan detail per kategori tool.")
def doctor(verbose):
    """Jalankan System Diagnostics lengkap."""
    from kiibot.tools.doctor import run_doctor
    run_doctor(verbose=verbose)


@cli.command()
def workspace():
    """Manage challenge workspaces."""
    from kiibot.workspace.manager import WorkspaceManager
    wm = WorkspaceManager()
    ws_list = wm.list_workspaces()
    if not ws_list:
        output.warning("Belum ada workspace. Buat dengan: kiibot workspace create <nama>")
        return
    rows = [[w.get("name", "-"), w.get("path", "-"), w.get("created", "-")] for w in ws_list]
    output.table(
        "Daftar Workspace",
        [("Nama", "bright_cyan"), ("Path", "bright_white"), ("Dibuat", "dim")],
        rows,
        show_lines=True,
    )


@cli.command()
def tools():
    """Manage and inspect KIIBOT tools."""
    from kiibot.tools.registry import get_registry
    registry = get_registry()
    summary = registry.get_summary()
    rows = []
    for cat, stats in sorted(summary.items()):
        rows.append([
            cat.upper(),
            str(stats.get("total", 0)),
            str(stats.get("installed", 0)),
            str(stats.get("missing", 0)),
        ])
    output.table(
        "Ringkasan Status Tools per Kategori",
        [
            ("Kategori", "bright_cyan"),
            ("Total", "white"),
            ("Terinstall", "bright_green"),
            ("Hilang", "bright_red"),
        ],
        rows,
        show_lines=True,
    )


@cli.command()
@click.argument("cipher", required=True)
def solve(cipher):
    """Auto-solve cipher/token secara rekursif (Base64, Hex, ROT, XOR, dll.)."""
    output.section("Auto-Solver")
    from kiibot.analysis.solver import AutoSolver
    solver = AutoSolver()
    with output.status("Solver sedang menganalisis..."):
        result = solver.solve(cipher)

    if result.flag_found:
        output.success(f"FLAG DITEMUKAN: {result.flag_found}")
        output.info(f"Tingkat Keyakinan: {result.confidence:.1f}%")
        output.info(f"Rute Decode: {' -> '.join(result.transformations)}")
    else:
        output.warning("Tidak ditemukan format flag yang eksplisit.")
        if result.best_candidate:
            output.info(f"Kandidat terbaik ({result.confidence:.1f}%): {result.best_candidate}")

    if result.all_candidates:
        output.section("Kandidat Lain (Sorted by Readability Score)")
        rows = [[" -> ".join(t), f"{s:.1f}", txt[:80]] for txt, t, s in result.all_candidates[:8]]
        output.table(
            "Kandidat Decode",
            [("Rute", "bright_cyan"), ("Skor", "bright_yellow"), ("Hasil", "bright_white")],
            rows,
            show_lines=True,
        )


@cli.command()
@click.argument("file_path", required=True)
def analyze(file_path):
    """Analisis mendalam file apapun (magic bytes, entropy, hash, stego, checksec, flag hunter)."""
    from kiibot.analysis.file_analyzer import analyze_file
    with output.status(f"Menganalisis file: {file_path}"):
        try:
            report = analyze_file(file_path)
        except FileNotFoundError:
            output.error(f"File tidak ditemukan: {file_path}")
            return
        except Exception as e:
            output.error(f"Gagal menganalisis: {e}")
            return
    _print_analysis_report(report)


@cli.command()
@click.argument("text", required=True)
def crypto(text):
    """Decode otomatis semua encoding: Base64, Hex, ROT, XOR, Morse, Binary, JWT, dll."""
    output.section("Crypto Decoder")
    from kiibot.analysis.decoders import decode_all
    with output.status("Mencoba semua decoder..."):
        results = decode_all(text)

    if not results:
        output.warning("Tidak ada decoder yang berhasil mendekode teks ini.")
        return

    rows = [[r["type"], r["result"][:120]] for r in results]
    output.table(
        f"Hasil Decode ({len(results)} metode berhasil)",
        [("Tipe Encoding", "bright_cyan"), ("Hasil Decode", "bright_white")],
        rows,
        show_lines=True,
    )


@cli.command(name="hash")
@click.argument("text", required=True)
def hash_cmd(text):
    """Identifikasi jenis hash dan cetak informasi kriptografi."""
    output.section("Hash Identification")
    from kiibot.analysis.decoders import identify_hash
    candidates = identify_hash(text)
    output.key_value("Input", text)
    output.key_value("Panjang", f"{len(text)} karakter")
    if candidates and "Unknown Hash Format" not in candidates:
        output.section("Kemungkinan Algoritma Hash")
        for c in candidates:
            output.success(c)
        output.section("Perintah Cracking")
        output.info(f"hashcat -a 0 -m AUTO {text} /usr/share/wordlists/rockyou.txt")
        output.info("john --format=auto --wordlist=/usr/share/wordlists/rockyou.txt hash.txt")
    else:
        output.warning("Format hash tidak dikenali.")


@cli.command()
@click.argument("file_path", required=True)
def steg(file_path):
    """Analisis file gambar untuk steganografi (PNG, JPEG, BMP)."""
    output.section("Steganography Analyzer")
    _check_and_install_missing_tools(["exiftool", "zsteg", "steghide"])
    from kiibot.analysis.file_analyzer import analyze_file
    with output.status(f"Menganalisis file stego: {file_path}"):
        try:
            report = analyze_file(file_path)
        except FileNotFoundError:
            output.error(f"File tidak ditemukan: {file_path}")
            return

    output.key_value("File", report.filename)
    output.key_value("Tipe", report.description)
    output.key_value("Entropy", f"{report.entropy:.4f} — {report.entropy_desc}")

    if report.flags_found:
        output.section("FLAG DITEMUKAN")
        for flag in report.flags_found:
            output.success(flag)

    if report.stego_indicators:
        output.section("Indikator Steganografi Terdeteksi")
        for ind in report.stego_indicators:
            output.warning(ind)
    else:
        output.info("Tidak ada indikator steganografi sederhana yang terdeteksi.")

    output.section("Tools Stego Lanjutan — Perintah Siap Pakai")
    output.info(f"exiftool {file_path}")
    output.info(f"zsteg -a {file_path}")
    output.info(f"steghide extract -sf {file_path}")
    output.info(f"binwalk -Me {file_path}")
    output.info(f"stegseek {file_path} /usr/share/wordlists/rockyou.txt")


@cli.command()
@click.argument("action", type=click.Choice(["cyclic", "find"]))
@click.argument("value", required=True)
def pwn(action, value):
    """Buffer Overflow Toolkit: generate cyclic pattern / cari offset."""
    output.section("PWN / Binary Exploitation")
    from kiibot.analysis.pwn_tools import cyclic, cyclic_find
    if action == "cyclic":
        try:
            length = int(value)
        except ValueError:
            output.error("Panjang pattern harus berupa angka integer.")
            return
        pattern = cyclic(length)
        output.success(f"Pattern De Bruijn (panjang {length}):")
        output.panel(pattern, title="Cyclic Pattern", style="bright_cyan")
        output.section("Perintah Selanjutnya")
        output.info("Tempel pattern ke input program, lalu saat crash:")
        output.info("  kiibot pwn find <4_karakter_EIP_atau_hex_register>")
    else:
        try:
            val = int(value, 16) if value.startswith(("0x", "0X")) else value
            offset = cyclic_find(val)
        except Exception as e:
            output.error(f"Gagal mencari offset: {e}")
            return
        if offset == -1:
            output.error("Pattern tidak ditemukan. Pastikan crash terjadi dari cyclic pattern KIIBOT.")
        else:
            output.success(f"Offset ditemukan: {offset} bytes")
            output.info(f"Padding buffer overflow: {offset} bytes sebelum overwrite EIP/RIP.")


@cli.command()
@click.option("--n", required=True, type=int, help="RSA Modulus (N)")
@click.option("--e", required=True, type=int, help="Public exponent (e)")
@click.option("--c", "c_val", required=True, type=int, help="Ciphertext (C)")
def rsa(n, e, c_val):
    """Serang RSA CTF: Small-e (cube root) dan Wiener's attack."""
    output.section("RSA Solver — CTF Attack")
    from kiibot.analysis.rsa_solver import integer_nth_root, wieners_attack
    output.key_value("N (Modulus)", str(n))
    output.key_value("e (Exponent)", str(e))
    output.key_value("C (Ciphertext)", str(c_val))

    # Small-e attack
    if e <= 3:
        output.section(f"Small-e Attack (e={e})")
        m, exact = integer_nth_root(c_val, e)
        if exact:
            try:
                msg = m.to_bytes((m.bit_length() + 7) // 8, "big").decode("utf-8", errors="replace")
                output.success(f"Plaintext (integer): {m}")
                output.success(f"Plaintext (teks): {msg}")
            except Exception:
                output.success(f"Plaintext (integer): {m}")
        else:
            output.warning("Small-e attack gagal: C bukan pangkat e bulat sempurna.")

    # Wiener's attack
    output.section("Wiener's Attack (d kecil)")
    with output.status("Menjalankan Wiener's Attack..."):
        d = wieners_attack(e, n)
    if d:
        output.success(f"Private key d ditemukan: {d}")
        try:
            m = pow(c_val, d, n)
            msg = m.to_bytes((m.bit_length() + 7) // 8, "big").decode("utf-8", errors="replace")
            output.success(f"Plaintext (integer): {m}")
            output.success(f"Plaintext (teks): {msg}")
        except Exception as ex:
            output.warning(f"Dekripsi gagal: {ex}")
    else:
        output.warning("Wiener's Attack gagal: d tidak rentan.")


@cli.command()
@click.argument("file_path", required=True)
def forensics(file_path):
    """Triage forensik: file, PCAP, log, memory dump."""
    output.section("Forensics Triage Engine")
    from pathlib import Path
    p = Path(file_path)
    if not p.exists():
        output.error(f"Path tidak ditemukan: {file_path}")
        return

    ext = p.suffix.lower()
    if ext in (".pcap", ".pcapng", ".cap"):
        _check_and_install_missing_tools(["tshark"])
        output.info("Mendeteksi PCAP — menjalankan PCAP Analyzer...")
        from kiibot.analysis.pcap_analyzer import ProfessionalPCAPAnalyzer
        analyzer = ProfessionalPCAPAnalyzer(str(p))
        with output.status("Menjalankan 11 tools PCAP secara paralel..."):
            result = _run_async(analyzer.run_expert_pcap_battery())

        if result.get("flags_found"):
            output.section("FLAG DITEMUKAN DI PCAP")
            for flag in result["flags_found"]:
                output.success(flag)

        if result.get("dns_queries"):
            output.section("DNS Queries yang Mencurigakan")
            for q in result["dns_queries"][:20]:
                output.info(q)

        if result.get("credentials"):
            output.section("Credential Cleartext Ditemukan")
            for cred in result["credentials"][:10]:
                output.warning(cred)

        if result.get("http_traffic"):
            output.section("HTTP Traffic (Request/Response)")
            rows = []
            for h in result["http_traffic"][:15]:
                rows.append([h.get("src",""), h.get("method",""), h.get("uri","")[:60], h.get("code","")])
            output.table(
                "HTTP Traffic",
                [("Src IP","bright_cyan"),("Method","bright_yellow"),("URI","bright_white"),("Status","dim")],
                rows,
                show_lines=True,
            )

        if result.get("tls_sni"):
            output.section("TLS SNI (Domain HTTPS)")
            for sni in result["tls_sni"][:10]:
                output.info(sni)

    elif ext in (".log", ".txt", ".csv"):
        output.info("Mendeteksi file log — menjalankan Log Analyzer...")
        from kiibot.analysis.log_analyzer import DeepLogAnalyzer
        analyzer = DeepLogAnalyzer(file_path=str(p))
        with output.status("Menjalankan 9 sub-tools analisis log secara paralel..."):
            log_result = _run_async(analyzer.run_concurrent_battery())
        if log_result.get("flags_found"):
            output.section("FLAG DITEMUKAN DI LOG")
            for flag in log_result["flags_found"]:
                output.success(flag)
        if log_result.get("sqli_findings"):
            output.section(f"SQL Injection Terdeteksi ({len(log_result['sqli_findings'])} baris)")
            for line in log_result["sqli_findings"][:5]:
                output.warning(line)
        if log_result.get("xss_findings"):
            output.section(f"XSS Terdeteksi ({len(log_result['xss_findings'])} baris)")
            for line in log_result["xss_findings"][:5]:
                output.warning(line)
        if log_result.get("rce_findings"):
            output.section(f"RCE/Command Injection Terdeteksi ({len(log_result['rce_findings'])} baris)")
            for line in log_result["rce_findings"][:5]:
                output.warning(line)
        top_ips = log_result.get("top_ips", {})
        if top_ips.get("top_ips"):
            output.section("Top Attacker IPs")
            rows = [[ip, str(count)] for ip, count in top_ips["top_ips"][:10]]
            output.table("IP Teratas", [("IP","bright_red"),("Hit","bright_white")], rows)
        if log_result.get("beaconing", {}).get("beaconing_suspects"):
            output.section("Indikasi Beaconing / C2 Traffic")
            for s in log_result["beaconing"]["beaconing_suspects"][:5]:
                output.warning(f"{s['ip']} — {s['request_count']} req, interval rata-rata {s['avg_interval_sec']}s")

    else:
        output.info("Menjalankan File Analyzer untuk triase forensik...")
        from kiibot.analysis.forensics_engine import triage_forensics
        with output.status("Menjalankan triase forensik..."):
            res = triage_forensics(p)
        output.key_value("File", res.filename)
        if res.flags:
            output.section("FLAG DITEMUKAN")
            for f in res.flags:
                output.success(f)
        if hasattr(res, "iocs") and res.iocs:
            output.section("Indicators of Compromise (IoC)")
            for ioc in res.iocs[:20]:
                output.warning(ioc)


@cli.command(name="flag")
@click.argument("target", required=True)
def flag_hunt(target):
    """Cari flag CTF di dalam string teks atau direktori secara rekursif."""
    output.section("Flag Hunter")
    from pathlib import Path

    from kiibot.analysis.flag_hunter import hunt_in_bytes, hunt_in_path
    p = Path(target)
    with output.status(f"Mencari flag di: {target}"):
        if p.exists():
            # target adalah file atau direktori
            raw_results = hunt_in_path(p)  # returns [(file, flag, method)]
            flags = [(flag, f"{src} [{method}]") for src, flag, method in raw_results]
        else:
            # target adalah string teks langsung
            raw_results = hunt_in_bytes(target.encode("utf-8", errors="ignore"))
            flags = [(flag, f"Input Teks [{method}]") for flag, method in raw_results]

    if not flags:
        output.warning("Tidak ada flag yang ditemukan.")
        return

    output.success(f"{len(flags)} flag ditemukan!")
    rows = [[flag, source] for flag, source in flags]
    output.table(
        "Flag yang Ditemukan",
        [("Flag", "bright_green"), ("Sumber", "dim")],
        rows,
        show_lines=True,
    )


@cli.command()
@click.argument("question", required=True, nargs=-1)
def ask(question):
    """Tanyakan pertanyaan ke KIIBOT AI (analisis, CTF, SOC, DFIR)."""
    q_str = " ".join(question)
    output.section("KIIBOT AI Chat")
    output.info(f"Pertanyaan: {q_str}")

    from kiibot.core.ai_orchestrator import AIOrchestrator
    orchestrator = AIOrchestrator()
    if not orchestrator.is_available():
        output.error("AI tidak tersedia. Isi API key di configs/ai_keys.txt atau ai_keys.json.")
        return

    async def _get():
        return await orchestrator.ask_ai(q_str)

    with output.status("AI sedang memproses pertanyaan Anda..."):
        answer = _run_async(_get())

    output.section("Jawaban AI")
    output.markdown_output(answer)


@cli.command()
def blue():
    """Blue Team module (SIEM, MITRE ATT&CK, log hunting). Not yet implemented."""
    output.section("Blue Team Module")
    output.info("Blue Team MITRE ATT&CK Reference aktif.")
    output.info("Gunakan 'kiibot forensics <file>' untuk analisis SOC mendalam.")
    output.info("Gunakan 'kiibot ask <pertanyaan>' untuk konsultasi SIEM/Suricata/YARA ke AI.")
    output.warning("Modul Blue Team interaktif lengkap akan hadir di fase selanjutnya.")


if __name__ == "__main__":
    cli()
