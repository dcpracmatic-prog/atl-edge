"""
CLI de la capa de archivo .stok.

Uso:
  smart-token protect archivo.stl [--master SECRET] [--out archivo.stl.stok]
  smart-token open   archivo.stl.stok [--master SECRET] [--key archivo.stok.key] [-o out]
  smart-token status archivo.stl.stok
  smart-token demo   [archivo_muestra]

La fricción se persiste dentro del .stok.
La sk se entrega en archivo hermano .stok.key (no dentro del .stok).
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path


def _master_from_args(args) -> bytes:
    if getattr(args, "master", None):
        return args.master.encode("utf-8")
    env = os.environ.get("SMART_TOKEN_MASTER")
    if env:
        return env.encode("utf-8")
    return b"demo-master-secret"


def cmd_protect(args: argparse.Namespace) -> int:
    from .stok import protect_file

    master = _master_from_args(args)
    stok_path, key_path = protect_file(
        args.input,
        output_path=args.out,
        master_secret=master,
        tarpit_mode=args.tarpit_mode,
        tarpit_seconds=args.tarpit_seconds,
        friction_backend=args.backend,
        key_path=args.key,
    )
    print(f"Protegido: {args.input}")
    print(f"  .stok  : {stok_path}  ({stok_path.stat().st_size} bytes)")
    print(f"  clave  : {key_path}  ({key_path.stat().st_size} bytes)")
    print(f"  origen : {Path(args.input).stat().st_size} bytes")
    return 0


def cmd_open(args: argparse.Namespace) -> int:
    from .stok import open_stok, friction_status

    master = _master_from_args(args)
    force = bool(args.force_failure)

    print(f"Abriendo: {args.input}")
    before = friction_status(args.input)
    print(f"  Fricción previa : fail_count={before['friction_snapshot'].get('fail_count', 0)}")

    t0 = time.perf_counter()
    plaintext, info = open_stok(
        args.input,
        master_secret=master,
        key_path=args.key,
        force_failure=force,
        output_path=args.out,
        update_friction=True,
    )
    elapsed = time.perf_counter() - t0

    if plaintext is not None:
        print(f"  Resultado       : LEGÍTIMO — payload recuperado ({len(plaintext)} bytes)")
        if args.out:
            print(f"  Escrito en      : {args.out}")
        print(f"  Tiempo          : {elapsed:.3f}s")
        print(f"  Fricción final  : fail_count={info['friction_state'].get('fail_count', 0)} (reseteado)")
        return 0

    fr = info.get("friction_state") or {}
    action = (info.get("friction") or {}).get("action")
    print(f"  Resultado       : RECHAZADO (no recuperable)")
    print(f"  fail_count      : {fr.get('fail_count')}")
    print(f"  flag_fibonacci  : {fr.get('flag_fibonacci')}")
    print(f"  flag_persistencia: {fr.get('flag_persistencia')}")
    print(f"  tarpit_triggered: {fr.get('tarpit_triggered')}")
    print(f"  acción          : {action}")
    print(f"  Tiempo          : {elapsed:.3f}s")
    if info.get("mlkem_error"):
        print(f"  mlkem           : {info['mlkem_error']}")
    print(f"  Coherencia      : {info.get('coherence')}")
    return 1


def cmd_status(args: argparse.Namespace) -> int:
    from .stok import friction_status

    st = friction_status(args.input)
    snap = st["friction_snapshot"]
    print(f"Archivo : {st['path']}")
    print(f"Label   : {st['public_label']}")
    print(f"Coherencia objetivo : {st['target_coherence']:.6f}")
    print(f"sk embebida en .stok : {st.get('has_embedded_sk', False)}")
    print(f"Fricción:")
    print(f"  fail_count       : {snap.get('fail_count', 0)}")
    print(f"  flag_fibonacci   : {snap.get('flag_fibonacci', False)}")
    print(f"  flag_persistencia: {snap.get('flag_persistencia', False)}")
    print(f"  tarpit_triggered : {snap.get('tarpit_triggered', False)}")
    return 0


def _make_sample_stl(path: Path) -> None:
    stl = """solid sample_tetrahedron
  facet normal 0 0 0
    outer loop
      vertex 0 0 0
      vertex 1 0 0
      vertex 0 1 0
    endloop
  endfacet
  facet normal 0 0 0
    outer loop
      vertex 0 0 0
      vertex 1 0 0
      vertex 0 0 1
    endloop
  endfacet
  facet normal 0 0 0
    outer loop
      vertex 0 0 0
      vertex 0 1 0
      vertex 0 0 1
    endloop
  endfacet
  facet normal 0 0 0
    outer loop
      vertex 1 0 0
      vertex 0 1 0
      vertex 0 0 1
    endloop
  endfacet
endsolid sample_tetrahedron
"""
    path.write_text(stl, encoding="utf-8")


def cmd_demo(args: argparse.Namespace) -> int:
    from .stok import protect_file, open_stok, friction_status

    sample = Path(args.sample) if args.sample else Path("sample_cad.stl")
    if not sample.exists():
        print(f"Creando archivo de muestra: {sample}")
        _make_sample_stl(sample)

    master = _master_from_args(args)
    stok_path = sample.with_suffix(sample.suffix + ".stok")
    key_path = Path(str(stok_path) + ".key")
    recovered = sample.with_name(sample.stem + "_recovered" + sample.suffix)

    print("=" * 60)
    print("1. PROTEGER archivo real")
    print("=" * 60)
    out, kout = protect_file(
        sample,
        output_path=stok_path,
        master_secret=master,
        tarpit_mode=args.tarpit_mode,
        tarpit_seconds=args.tarpit_seconds,
        friction_backend=args.backend,
        key_path=key_path,
    )
    print(f"   {sample} ({sample.stat().st_size} B)")
    print(f"   → {out} ({out.stat().st_size} B)  [sin sk]")
    print(f"   → {kout} ({kout.stat().st_size} B)  [sk fuera de banda]")
    print(f"   Estado inicial: {friction_status(stok_path)['friction_snapshot']}")

    print()
    print("=" * 60)
    print("2. APERTURA LEGÍTIMA (master + key correctos)")
    print("=" * 60)
    t0 = time.perf_counter()
    pt, info = open_stok(
        stok_path,
        master_secret=master,
        key_path=key_path,
        output_path=recovered,
        update_friction=True,
    )
    elapsed = time.perf_counter() - t0
    assert pt is not None and pt == sample.read_bytes()
    print(f"   OK — payload recuperado ({len(pt)} B) en {elapsed:.3f}s")
    print(f"   Escrito: {recovered}")
    print(f"   Fricción tras éxito: {info['friction_state']}")

    print()
    print("=" * 60)
    print("3. INTENTOS NO AUTORIZADOS (fuerza bruta)")
    print("=" * 60)
    print("   Master incorrecto; la sk correcta está presente.")
    print("   El estado de fricción se persiste en el .stok.")
    print()

    for i in range(1, 5):
        wrong = master + b"-wrong-" + str(i).encode()
        t0 = time.perf_counter()
        pt, info = open_stok(
            stok_path,
            master_secret=wrong,
            key_path=key_path,
            update_friction=True,
        )
        elapsed = time.perf_counter() - t0
        fr = info.get("friction_state") or {}
        action = (info.get("friction") or {}).get("action")
        print(f"   Intento {i}:")
        print(f"     recoverable     : {info.get('recoverable')}")
        print(f"     fail_count      : {fr.get('fail_count')}")
        print(f"     flag_fibonacci  : {fr.get('flag_fibonacci')}")
        print(f"     flag_persistencia: {fr.get('flag_persistencia')}")
        print(f"     tarpit_triggered: {fr.get('tarpit_triggered')}")
        print(f"     acción          : {action}")
        print(f"     tiempo          : {elapsed:.3f}s")
        print()

    print("=" * 60)
    print("4. ESTADO FINAL EN EL ARCHIVO .stok")
    print("=" * 60)
    print(f"   {friction_status(stok_path)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="smart-token",
        description="Smart Token Prod — protección de archivos con fricción anti-fuerza-bruta",
    )
    p.add_argument("--master", default=None, help="Secreto maestro (o SMART_TOKEN_MASTER)")
    p.add_argument(
        "--backend",
        choices=["auto", "native", "python"],
        default="auto",
    )
    p.add_argument(
        "--tarpit-mode",
        choices=["cpu", "mutate", "block"],
        default="cpu",
        dest="tarpit_mode",
    )
    p.add_argument(
        "--tarpit-seconds",
        type=float,
        default=1.0,
        dest="tarpit_seconds",
    )

    sub = p.add_subparsers(dest="command", required=True)

    p_protect = sub.add_parser("protect", help="Cifrar un archivo → .stok + .stok.key")
    p_protect.add_argument("input", help="Archivo a proteger")
    p_protect.add_argument("--out", "-o", default=None, help="Ruta del .stok")
    p_protect.add_argument("--key", default=None, help="Ruta del archivo de clave (default: <stok>.key)")
    p_protect.set_defaults(func=cmd_protect)

    p_open = sub.add_parser("open", help="Intentar abrir un .stok")
    p_open.add_argument("input", help="Archivo .stok")
    p_open.add_argument("--out", "-o", default=None, help="Escribir payload recuperado")
    p_open.add_argument("--key", default=None, help="Archivo de clave .stok.key")
    p_open.add_argument("--force-failure", action="store_true")
    p_open.set_defaults(func=cmd_open)

    p_status = sub.add_parser("status", help="Estado de fricción del .stok")
    p_status.add_argument("input", help="Archivo .stok")
    p_status.set_defaults(func=cmd_status)

    p_demo = sub.add_parser("demo", help="Demo: protect + legítimo + fuerza bruta")
    p_demo.add_argument("sample", nargs="?", default=None)
    p_demo.set_defaults(func=cmd_demo)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
