#!/usr/bin/env python3
"""Prueba de autenticidad AES-GCM del Laboratorio 4.

Usa la misma función `resolver` que el descifrador principal. Comprueba
la captura original y altera un solo bit del último byte del tag AES-GCM
de la trama 2, en una copia temporal del PCAP. No modifica los originales.

Uso: py -3 probar_integridad.py
Requiere resolver_actividad2.py y los archivos del profesor en la misma carpeta.
"""
from pathlib import Path
import struct
from tempfile import TemporaryDirectory

from resolver_actividad2 import AES_MARKER, paquetes_pcap, resolver

CARPETA = Path(__file__).resolve().parent
CAPTURA = CARPETA / "transacciones_cifradas.pcap"
PRIVADA = CARPETA / "clave_privada.pem"
PUBLICA = CARPETA / "clave_publica.pem"


def alterar_tag_en_copia(original: bytes) -> bytes:
    """Altera exactamente un bit del tag de la trama AES-GCM 2."""
    datos = bytearray(original)
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
              b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}.get(bytes(datos[:4]))
    if endian is None:
        raise ValueError("La captura no es un PCAP clasico valido")

    pos = 24
    trama = 0
    while pos < len(datos):
        if pos + 16 > len(datos):
            raise ValueError("Cabecera de trama PCAP incompleta")
        longitud = struct.unpack_from(endian + "I", datos, pos + 8)[0]
        inicio = pos + 16
        fin = inicio + longitud
        if fin > len(datos):
            raise ValueError("Trama PCAP truncada")
        trama += 1
        if trama == 2:
            # La trama 2 del archivo entregado tiene la carga AESGCM| al final.
            paquete_original = next((p for n, p in paquetes_pcap(CAPTURA) if n == 2), None)
            if (not paquete_original or not paquete_original.startswith(AES_MARKER)
                    or len(paquete_original) < len(AES_MARKER) + 12 + 16):
                raise ValueError("La trama 2 no contiene una carga AES-GCM valida")
            if bytes(datos[inicio:fin]).endswith(paquete_original) is False:
                raise ValueError("No se pudo localizar el tag al final de la trama 2")
            datos[fin - 1] ^= 0x01  # Un bit del ultimo byte del tag de 16 bytes
            return bytes(datos)
        pos = fin
    raise ValueError("No se encontro la trama 2")


def main():
    for archivo in (CAPTURA, PRIVADA, PUBLICA):
        if not archivo.is_file():
            raise FileNotFoundError(f"Falta archivo: {archivo.name}")

    _, _, _, transacciones, _ = resolver(CAPTURA, PRIVADA, PUBLICA)
    if len(transacciones) != 40:
        raise AssertionError(f"Se esperaban 40 transacciones, se recuperaron {len(transacciones)}")
    print("PRUEBA 1 - Captura original: PASS")
    print("  Transacciones AES-GCM autenticadas: 40/40")

    copia_modificada = alterar_tag_en_copia(CAPTURA.read_bytes())
    with TemporaryDirectory(prefix="lab4_integridad_") as directorio:
        archivo_temporal = Path(directorio) / "captura_modificada_temporal.pcap"
        archivo_temporal.write_bytes(copia_modificada)
        try:
            resolver(archivo_temporal, PRIVADA, PUBLICA)
        except ValueError as exc:
            if "autenticaci" not in str(exc).lower() or "trama 2" not in str(exc).lower():
                raise AssertionError(f"Fallo inesperado: {exc}") from exc
        else:
            raise AssertionError("FALLO: el programa acepto un tag AES-GCM alterado")

    print("PRUEBA 2 - Tag AES-GCM modificado (trama 2): PASS")
    print("  Resultado esperado: autenticacion rechazada (InvalidTag)")
    print("RESULTADO FINAL: PASS (integridad y autenticidad verificadas)")
    print("Los archivos originales no fueron modificados.")


if __name__ == "__main__":
    main()
