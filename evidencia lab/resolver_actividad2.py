#!/usr/bin/env python3
"""Laboratorio 4: recuperar PIN RSA y transacciones AES-GCM desde una captura PCAP.

Uso:
    python resolver_actividad2.py transacciones_cifradas.pcap clave_privada.pem --publica clave_publica.pem --salida resultados_actividad2.txt --resumen

Dependencia externa: cryptography (pip install cryptography)
No copia ni modifica ninguna clave privada.
"""

import argparse
from pathlib import Path
import struct
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

RSA_MARKER = b"RSA_PIN|"
AES_MARKER = b"AESGCM|"


def paquetes_pcap(ruta: Path):
    """Itera (numero_de_trama, TCP payload) sobre PCAP clásico (no pcapng)."""
    data = ruta.read_bytes()
    if len(data) < 24:
        raise ValueError("El archivo no contiene una cabecera PCAP válida")
    endian = {
        b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">",
    }.get(data[:4])
    if endian is None:
        raise ValueError("Se requiere un archivo .pcap clásico (no .pcapng)")
    enlace = struct.unpack_from(endian + "I", data, 20)[0]
    if enlace not in (1, 12, 101, 228):
        raise ValueError(f"Tipo de enlace PCAP no admitido: {enlace}")

    pos, numero = 24, 0
    while pos < len(data):
        if len(data) - pos < 16:
            raise ValueError("Registro PCAP incompleto")
        _, _, largo, _ = struct.unpack_from(endian + "IIII", data, pos)
        pos += 16
        if len(data) - pos < largo:
            raise ValueError("Paquete PCAP truncado")
        trama = data[pos:pos + largo]
        pos += largo
        numero += 1

        # La captura entregada usa LINKTYPE_IPV4 (228): IP desde el primer byte.
        if enlace == 1:  # Ethernet
            if len(trama) < 14:
                continue
            etipo = int.from_bytes(trama[12:14], "big")
            inicio = 14
            if etipo == 0x8100 and len(trama) >= 18:  # VLAN 802.1Q
                etipo = int.from_bytes(trama[16:18], "big")
                inicio = 18
            if etipo != 0x0800:
                continue
            ip = trama[inicio:]
        else:
            ip = trama

        if len(ip) < 20 or ip[0] >> 4 != 4:
            continue
        ihl = (ip[0] & 15) * 4
        if ihl < 20 or len(ip) < ihl + 20 or ip[9] != 6:
            continue
        # Los datos entregados no tienen fragmentación IPv4; no interpretar
        # fragmentos incompletos como si fueran mensajes TCP independientes.
        if int.from_bytes(ip[6:8], "big") & 0x3FFF:
            raise ValueError(f"Fragmentación IPv4 en la trama {numero}: se requiere reensamblado")
        ip_total = int.from_bytes(ip[2:4], "big")
        if ip_total < ihl + 20 or len(ip) < ip_total:
            continue
        ip = ip[:ip_total]
        tcp = ip[ihl:]
        thl = (tcp[12] >> 4) * 4
        if thl < 20 or len(tcp) < thl:
            continue
        contenido = tcp[thl:]
        if contenido:
            yield numero, contenido


def resolver(ruta_pcap: Path, ruta_privada: Path, ruta_publica: Path | None):
    privada = serialization.load_pem_private_key(ruta_privada.read_bytes(), password=None)
    if not isinstance(privada, rsa.RSAPrivateKey):
        raise ValueError("La clave privada no es RSA")
    if ruta_publica:
        publica = serialization.load_pem_public_key(ruta_publica.read_bytes())
        if not isinstance(publica, rsa.RSAPublicKey) or publica.public_numbers() != privada.public_key().public_numbers():
            raise ValueError("Las claves RSA pública y privada no corresponden al mismo par")

    paquetes = list(paquetes_pcap(ruta_pcap))
    rsa_paquetes = [(n, p) for n, p in paquetes if p.startswith(RSA_MARKER)]
    aes_paquetes = [(n, p) for n, p in paquetes if p.startswith(AES_MARKER)]
    if len(rsa_paquetes) != 1:
        raise ValueError(f"Se esperaba 1 paquete RSA_PIN, se encontraron {len(rsa_paquetes)}")
    if not aes_paquetes:
        raise ValueError("No se encontraron paquetes AESGCM")

    numero_rsa, cuerpo_rsa = rsa_paquetes[0]
    contenido = cuerpo_rsa[len(RSA_MARKER):]
    longitud_rsa = privada.key_size // 8
    if len(contenido) != 16 + longitud_rsa:
        raise ValueError(f"Longitud inesperada de RSA_PIN: {len(contenido)} bytes")
    salt, pin_cifrado = contenido[:16], contenido[16:]
    pin = privada.decrypt(
        pin_cifrado,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )
    if len(pin) != 4 or not all(48 <= c <= 57 for c in pin):
        raise ValueError("El PIN recuperado no tiene cuatro dígitos")
    clave_aes = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(pin)
    aes = AESGCM(clave_aes)
    resultados = []
    for numero, paquete in aes_paquetes:
        contenido = paquete[len(AES_MARKER):]
        if len(contenido) < 12 + 16:
            raise ValueError(f"Trama {numero}: AES-GCM demasiado corto")
        nonce, cifrado_y_tag = contenido[:12], contenido[12:]
        try:
            texto = aes.decrypt(nonce, cifrado_y_tag, None).decode("utf-8")
        except InvalidTag as exc:
            raise ValueError(f"Trama {numero}: autenticación AES-GCM fallida") from exc
        resultados.append((numero, texto))
    return numero_rsa, salt, pin.decode("ascii"), resultados, len(paquetes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="Archivo .pcap del profesor")
    parser.add_argument("privada", type=Path, help="Clave privada RSA .pem")
    parser.add_argument("--publica", type=Path, help="Clave pública RSA .pem (verificación opcional)")
    parser.add_argument("--salida", type=Path, default=Path("resultados_actividad2.txt"))
    parser.add_argument("--resumen", action="store_true", help="Mostrar solo las tres primeras transacciones en terminal")
    args = parser.parse_args()
    try:
        trama_rsa, salt, pin, resultados, cantidad_tcp = resolver(args.pcap, args.privada, args.publica)
        lineas = [
            "ACTIVIDAD 2 - RESULTADOS VERIFICADOS",
            f"Paquete RSA_PIN: trama {trama_rsa}",
            f"Salt (16 bytes): {salt.hex()}",
            "RSA-OAEP: SHA-256 / MGF1-SHA256",
            f"PIN recuperado mediante RSA: {pin}",
            "Scrypt: n=16384, r=8, p=1; clave AES-256 (32 bytes)",
            f"Transacciones AES-GCM encontradas: {len(resultados)}",
            f"Autenticación AES-GCM: {len(resultados)}/{len(resultados)} correcta",
            "",
            "TRANSACCIONES RECUPERADAS (FORMATO ORIGINAL)",
        ]
        for i, (trama, texto) in enumerate(resultados, 1):
            lineas.append(f"[{i:02d} / trama {trama}] {texto}")
        args.salida.parent.mkdir(parents=True, exist_ok=True)
        args.salida.write_text("\n".join(lineas) + "\n", encoding="utf-8")
        encabezado = lineas[:8]
        print("\n".join(encabezado))
        print("\nTRANSACCIONES RECUPERADAS (FORMATO ORIGINAL)")
        imprimir = resultados[:3] if args.resumen else resultados
        for i, (trama, texto) in enumerate(imprimir, 1):
            print(f"[{i:02d} / trama {trama}] {texto}")
        if args.resumen:
            print(f"... otras {len(resultados) - len(imprimir)} transacciones en {args.salida}")
        print(f"\nArchivo completo: {args.salida}")
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
