#!/usr/bin/env python3
"""
flutter_http_monitor.py — auto-locate BoringSSL SSL_read / SSL_write in a stripped
libflutter.so (arm64) and generate a ready-to-run Frida monitor script.

Works across Flutter versions: instead of hardcoded offsets it fingerprints the
functions structurally, anchored on engine strings that are stable across builds:
  - "secure_socket_filter.cc"  (Dart's TLS filter, which BL-calls SSL_read/SSL_write)
  - the shared OPENSSL_PUT_ERROR helper + the (field-load / line-imm / return -1) shape
Direction (read vs write) is disambiguated by how the Dart caller treats the result
(SSL_read result is clamped >=0; SSL_write result is tested for negative-as-error).

Usage:
  python3 flutter_http_monitor.py libflutter.so
  python3 flutter_http_monitor.py app.apk                 # pulls lib/arm64-v8a/libflutter.so
  python3 flutter_http_monitor.py libflutter.so -o monitor.js
  python3 flutter_http_monitor.py libflutter.so --print-only

Deps:  pip install capstone pyelftools
"""

import argparse, base64, bisect, io, os, re, sys, zipfile
from collections import Counter

try:
    from elftools.elf.elffile import ELFFile
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    sys.exit("Missing deps. Run:  pip install capstone pyelftools")

ANCHOR_FILTER = b"secure_socket_filter.cc"

# The Frida monitor template is embedded (base64) so this tool is a single
# portable file. Override with --template to use an external .js instead.
# To refresh after editing the .js:  python3 flutter_http_monitor.py --embed flutter-http-monitor.js
EMBEDDED_TEMPLATE_B64 = "LyoKICogZmx1dHRlci1odHRwLW1vbml0b3IKICogRGVjcnlwdGVkIEhUVFAgdHJhZmZpYyBtb25pdG9yIGZvciBGbHV0dGVyIGFwcHMgKEJvcmluZ1NTTCBob29rIGluIGxpYmZsdXR0ZXIuc28pLgogKgogKiBGZWF0dXJlczogcmVhc3NlbWJsZXMgVExTIGNodW5rcywgZGUtY2h1bmtzIFRyYW5zZmVyLUVuY29kaW5nLCBpbmZsYXRlcyBnemlwLAogKiBwcmV0dHktcHJpbnRzIEpTT04sIGFuZCBhIEJ1cnAtc3R5bGUgU0NPUEUgc28geW91IG9ubHkgd2F0Y2ggdGhlIGhvc3RzIHlvdSBjYXJlIGFib3V0LgogKgogKiBPZmZzZXRzIGJlbG93IGFyZSBmb3IgT05FIHNwZWNpZmljIGxpYmZsdXR0ZXIuc28gYnVpbGQuIEZvciBhbnkgb3RoZXIgYnVpbGQsCiAqIHJlZ2VuZXJhdGUgdGhlbSB3aXRoIGZsdXR0ZXJfc3NsX2ZpbmRlci5weSAoaXQgcGF0Y2hlcyB0aGVzZSB0d28gY29uc3RhbnRzKToKICogICBTU0xfd3JpdGUgICByZXF1ZXN0ICAgKGJ1ZmZlciB2YWxpZCBvbiBFTlRFUiwgbGVuID0gYXJnMikKICogICBTU0xfcmVhZCAgICByZXNwb25zZSAgKGJ1ZmZlciB2YWxpZCBvbiBMRUFWRSwgbGVuID0gcmV0dmFsKQogKiBJZiBhIGJ1aWxkIGV2ZXIgc2hvd3MgcmVxdWVzdHMvcmVzcG9uc2VzIHN3YXBwZWQsIHN3YXAgdGhlIHR3byBjb25zdGFudHMuCiAqCiAqIFVzYWdlOgogKiAgIGZyaWRhIC1VIC1mIDxwYWNrYWdlPiAtbCBmbHV0dGVyLWh0dHAtbW9uaXRvci5qcwogKgogKiBMaXZlIHNjb3BlIGNvbnRyb2wgKHR5cGUgdGhlc2UgaW4gdGhlIEZyaWRhIFJFUEwgd2hpbGUgaXQgcnVucyk6CiAqICAgYWRkU2NvcGUoJ2FwaS5leGFtcGxlLmNvbScpICAgICAgICAgICAgLy8gYWRkIG9uZSBvciBtb3JlIGhvc3RzICh3aWxkY2FyZHMgb2s6ICcqLmV4YW1wbGUuY29tJykKICogICBhZGRTY29wZSgnYS5jb20nLCAnYi5jb20nKSAgICAgICAgICAgICAvLyBhZGQgc2V2ZXJhbCBhdCBvbmNlCiAqICAgcmVtb3ZlU2NvcGUoJ2EuY29tJykgICAgICAgICAgICAgICAgICAgLy8gcmVtb3ZlIGEgaG9zdAogKiAgIGNsZWFyU2NvcGUoKSAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIGVtcHR5IHRoZSBzY29wZSAodGhlbiBldmVyeXRoaW5nIHNob3dzKQogKiAgIGxpc3RTY29wZSgpICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIHByaW50IGN1cnJlbnQgc2NvcGUKICogICBzY29wZU9ubHkodHJ1ZXxmYWxzZSkgICAgICAgICAgICAgICAgICAvLyB0cnVlID0gb25seSBpbi1zY29wZSBob3N0cyBwcmludCAoZGVmYXVsdCksIGZhbHNlID0gc2hvdyBhbGwKICovCgondXNlIHN0cmljdCc7Cgpjb25zdCBTU0xfV1JJVEVfT0ZGID0gMHg3M2MxMGM7CmNvbnN0IFNTTF9SRUFEX09GRiAgPSAweDczYjkwMDsKY29uc3QgRkxVU0hfSURMRV9NUyA9IDMwMDsKY29uc3QgUFJFVFRZX0pTT04gICAgPSB0cnVlOwpjb25zdCBIRVhEVU1QX0JJTkFSWSA9IHRydWU7CmNvbnN0IFVTRV9DT0xPUiAgICAgID0gdHJ1ZTsgIC8vIHNldCBmYWxzZSBpZiB5b3VyIHRlcm1pbmFsIHNob3dzIHJhdyBlc2NhcGUgY29kZXMKCmNvbnN0IEMgPSB7CiAgcmVzZXQ6ICdceDFiWzBtJywgZGltOiAnXHgxYls5MG0nLCBib2xkOiAnXHgxYlsxbScsCiAgY3lhbjogJ1x4MWJbMzZtJywgZ3JlZW46ICdceDFiWzMybScsIHllbGxvdzogJ1x4MWJbMzNtJywgcmVkOiAnXHgxYlszMW0nLAp9OwpmdW5jdGlvbiBjb2woYywgcykgeyByZXR1cm4gVVNFX0NPTE9SID8gYyArIHMgKyBDLnJlc2V0IDogczsgfQoKLy8gPT09PT09PT09PT09PT09PT09PT09IFNDT1BFIChCdXJwLXN0eWxlKSA9PT09PT09PT09PT09PT09PT09PT0KLy8gQWRkIHRoZSBob3N0cyB5b3Ugd2FudCB0byBtb25pdG9yIGhlcmUsIG9yIG1hbmFnZSBsaXZlIGZyb20gdGhlIFJFUEwgd2l0aAovLyBhZGRTY29wZSgneW91ci5ob3N0JykuIExlYXZlIGVtcHR5IHRvIHNob3cgQUxMIGhvc3RzIChkZWZhdWx0KS4KdmFyIFNDT1BFID0gW107Ci8vIFdoZW4gdHJ1ZSwgb25seSBpbi1zY29wZSBob3N0cyBwcmludC4gV2hlbiBTQ09QRSBpcyBlbXB0eSwgZXZlcnl0aGluZyBwcmludHMuCnZhciBTQ09QRV9PTkxZID0gdHJ1ZTsKCmZ1bmN0aW9uIF9ub3JtKGgpIHsgcmV0dXJuIChoIHx8ICcnKS50b0xvd2VyQ2FzZSgpLnRyaW0oKTsgfQpmdW5jdGlvbiBob3N0TWF0Y2hlcyhob3N0KSB7CiAgaWYgKFNDT1BFLmxlbmd0aCA9PT0gMCkgcmV0dXJuIHRydWU7ICAgICAgICAgIC8vIGVtcHR5IHNjb3BlID0+IGV2ZXJ5dGhpbmcgaW4gc2NvcGUKICBob3N0ID0gX25vcm0oaG9zdCk7CiAgaWYgKCFob3N0KSByZXR1cm4gZmFsc2U7ICAgICAgICAgICAgICAgICAgICAgICAvLyB1bmtub3duIGhvc3Qgd2hpbGUgc2NvcGUgaXMgc2V0ID0+IG91dAogIGNvbnN0IGJhcmUgPSBob3N0LnNwbGl0KCc6JylbMF07ICAgICAgICAgICAgICAgLy8gc3RyaXAgOnBvcnQKICBmb3IgKGNvbnN0IHJhdyBvZiBTQ09QRSkgewogICAgY29uc3QgcCA9IF9ub3JtKHJhdyk7CiAgICBpZiAocC5pbmRleE9mKCcqJykgPj0gMCkgewogICAgICBjb25zdCByZSA9IG5ldyBSZWdFeHAoJ14nICsgcC5yZXBsYWNlKC9bLis/XiR7fSgpfFtcXVxcXS9nLCAnXFwkJicpLnJlcGxhY2UoL1wqL2csICcuKicpICsgJyQnKTsKICAgICAgaWYgKHJlLnRlc3QoaG9zdCkgfHwgcmUudGVzdChiYXJlKSkgcmV0dXJuIHRydWU7CiAgICB9IGVsc2UgaWYgKGhvc3QuaW5kZXhPZihwKSA+PSAwKSB7CiAgICAgIHJldHVybiB0cnVlOyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBzdWJzdHJpbmcgbWF0Y2ggKGhhbmRsZXMgaG9zdDpwb3J0KQogICAgfQogIH0KICByZXR1cm4gZmFsc2U7Cn0KZnVuY3Rpb24gc2hvdWxkU2hvdyhob3N0KSB7IHJldHVybiAhU0NPUEVfT05MWSB8fCBTQ09QRS5sZW5ndGggPT09IDAgfHwgaG9zdE1hdGNoZXMoaG9zdCk7IH0KCi8vIC0tLS0gbGl2ZSBjb250cm9scyAoY2FsbGFibGUgZnJvbSB0aGUgRnJpZGEgUkVQTCkgLS0tLQpmdW5jdGlvbiBsaXN0U2NvcGUoKSB7IGNvbnNvbGUubG9nKCdbc2NvcGVdICcgKyAoU0NPUEUubGVuZ3RoID8gU0NPUEUuam9pbignLCAnKSA6ICcoZW1wdHkg4oCUIGFsbCBob3N0cyBzaG93biknKSArICcgICBzY29wZU9ubHk9JyArIFNDT1BFX09OTFkpOyByZXR1cm4gU0NPUEUuc2xpY2UoKTsgfQpmdW5jdGlvbiBhZGRTY29wZSgpIHsKICBjb25zdCBpdGVtcyA9IEFycmF5LnByb3RvdHlwZS5jb25jYXQuYXBwbHkoW10sIEFycmF5LmZyb20oYXJndW1lbnRzKSk7IC8vIGZsYXR0ZW4gYXJncy9hcnJheXMKICBmb3IgKGNvbnN0IGggb2YgaXRlbXMpIHsgY29uc3QgdiA9IF9ub3JtKGgpOyBpZiAodiAmJiBTQ09QRS5pbmRleE9mKHYpIDwgMCkgU0NPUEUucHVzaCh2KTsgfQogIHJldHVybiBsaXN0U2NvcGUoKTsKfQpmdW5jdGlvbiByZW1vdmVTY29wZShoKSB7IGNvbnN0IHYgPSBfbm9ybShoKTsgY29uc3QgaSA9IFNDT1BFLmluZGV4T2Yodik7IGlmIChpID49IDApIFNDT1BFLnNwbGljZShpLCAxKTsgcmV0dXJuIGxpc3RTY29wZSgpOyB9CmZ1bmN0aW9uIGNsZWFyU2NvcGUoKSB7IFNDT1BFLmxlbmd0aCA9IDA7IHJldHVybiBsaXN0U2NvcGUoKTsgfQpmdW5jdGlvbiBzY29wZU9ubHkoYikgeyBTQ09QRV9PTkxZID0gISFiOyByZXR1cm4gbGlzdFNjb3BlKCk7IH0KLy8gcHJvZ3JhbW1hdGljIGFjY2VzcyB0b286IGZyaWRhIC4uLiAtZSAicnBjLmV4cG9ydHMuYWRkc2NvcGUoJ3gnKSIKcnBjLmV4cG9ydHMgPSB7CiAgYWRkc2NvcGU6IGZ1bmN0aW9uICgpIHsgcmV0dXJuIGFkZFNjb3BlLmFwcGx5KG51bGwsIGFyZ3VtZW50cyk7IH0sCiAgcmVtb3Zlc2NvcGU6IHJlbW92ZVNjb3BlLCBjbGVhcnNjb3BlOiBjbGVhclNjb3BlLCBsaXN0c2NvcGU6IGxpc3RTY29wZSwgc2NvcGVvbmx5OiBzY29wZU9ubHksCn07CgovLyA9PT09PT09PT09PT09PT09PT09PT0gYnl0ZSBoZWxwZXJzID09PT09PT09PT09PT09PT09PT09PQpmdW5jdGlvbiB1dGY4KGJ5dGVzKSB7CiAgbGV0IG91dCA9ICcnLCBpID0gMDsgY29uc3QgbiA9IGJ5dGVzLmxlbmd0aDsKICB3aGlsZSAoaSA8IG4pIHsKICAgIGNvbnN0IGIgPSBieXRlc1tpXTsKICAgIGlmIChiIDwgMHg4MCkgeyBvdXQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShiKTsgaSsrOyB9CiAgICBlbHNlIGlmIChiID49IDB4YzAgJiYgYiA8IDB4ZTAgJiYgaSArIDEgPCBuKSB7IG91dCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKCgoYiAmIDB4MWYpIDw8IDYpIHwgKGJ5dGVzW2kgKyAxXSAmIDB4M2YpKTsgaSArPSAyOyB9CiAgICBlbHNlIGlmIChiID49IDB4ZTAgJiYgYiA8IDB4ZjAgJiYgaSArIDIgPCBuKSB7IG91dCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKCgoYiAmIDB4MGYpIDw8IDEyKSB8ICgoYnl0ZXNbaSArIDFdICYgMHgzZikgPDwgNikgfCAoYnl0ZXNbaSArIDJdICYgMHgzZikpOyBpICs9IDM7IH0KICAgIGVsc2UgaWYgKGIgPj0gMHhmMCAmJiBpICsgMyA8IG4pIHsgY29uc3QgY3AgPSAoKGIgJiAweDA3KSA8PCAxOCkgfCAoKGJ5dGVzW2kgKyAxXSAmIDB4M2YpIDw8IDEyKSB8ICgoYnl0ZXNbaSArIDJdICYgMHgzZikgPDwgNikgfCAoYnl0ZXNbaSArIDNdICYgMHgzZik7IGNvbnN0IGMgPSBjcCAtIDB4MTAwMDA7IG91dCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKDB4ZDgwMCArIChjID4+IDEwKSwgMHhkYzAwICsgKGMgJiAweDNmZikpOyBpICs9IDQ7IH0KICAgIGVsc2UgeyBvdXQgKz0gJy4nOyBpKys7IH0KICB9CiAgcmV0dXJuIG91dDsKfQpmdW5jdGlvbiBjb25jYXQoY2h1bmtzKSB7IGxldCB0ID0gMDsgZm9yIChjb25zdCBjIG9mIGNodW5rcykgdCArPSBjLmxlbmd0aDsgY29uc3QgbyA9IG5ldyBVaW50OEFycmF5KHQpOyBsZXQgcCA9IDA7IGZvciAoY29uc3QgYyBvZiBjaHVua3MpIHsgby5zZXQoYywgcCk7IHAgKz0gYy5sZW5ndGg7IH0gcmV0dXJuIG87IH0KZnVuY3Rpb24gZmluZFNlcShiLCBzZXEsIHN0YXJ0KSB7IG91dGVyOiBmb3IgKGxldCBpID0gc3RhcnQ7IGkgPD0gYi5sZW5ndGggLSBzZXEubGVuZ3RoOyBpKyspIHsgZm9yIChsZXQgaiA9IDA7IGogPCBzZXEubGVuZ3RoOyBqKyspIGlmIChiW2kgKyBqXSAhPT0gc2VxW2pdKSBjb250aW51ZSBvdXRlcjsgcmV0dXJuIGk7IH0gcmV0dXJuIC0xOyB9CmNvbnN0IENSTEYgPSBbMTMsIDEwXSwgQ1JMRjIgPSBbMTMsIDEwLCAxMywgMTBdOwpmdW5jdGlvbiBpc0d6aXAoYikgeyByZXR1cm4gYi5sZW5ndGggPj0gMiAmJiBiWzBdID09PSAweDFmICYmIGJbMV0gPT09IDB4OGI7IH0KCi8vID09PT09PT09PT09PT09PT09PT09PSB0aW55LWluZmxhdGUgKE1JVCkgKyBndW56aXAgPT09PT09PT09PT09PT09PT09PT09CmZ1bmN0aW9uIFRyZWUoKSB7IHRoaXMudGFibGUgPSBuZXcgVWludDE2QXJyYXkoMTYpOyB0aGlzLnRyYW5zID0gbmV3IFVpbnQxNkFycmF5KDI4OCk7IH0KZnVuY3Rpb24gSURhdGEocywgZCkgeyB0aGlzLnMgPSBzOyB0aGlzLmkgPSAwOyB0aGlzLnQgPSAwOyB0aGlzLmJpdGNvdW50ID0gMDsgdGhpcy5kZXN0ID0gZDsgdGhpcy5kZXN0TGVuID0gMDsgdGhpcy5sdHJlZSA9IG5ldyBUcmVlKCk7IHRoaXMuZHRyZWUgPSBuZXcgVHJlZSgpOyB9CnZhciBfc2wgPSBuZXcgVHJlZSgpLCBfc2QgPSBuZXcgVHJlZSgpOwp2YXIgX2xiaXRzID0gbmV3IFVpbnQ4QXJyYXkoMzApLCBfbGJhc2UgPSBuZXcgVWludDE2QXJyYXkoMzApLCBfZGJpdHMgPSBuZXcgVWludDhBcnJheSgzMCksIF9kYmFzZSA9IG5ldyBVaW50MTZBcnJheSgzMCk7CnZhciBfY2xjID0gbmV3IFVpbnQ4QXJyYXkoWzE2LCAxNywgMTgsIDAsIDgsIDcsIDksIDYsIDEwLCA1LCAxMSwgNCwgMTIsIDMsIDEzLCAyLCAxNCwgMSwgMTVdKTsKdmFyIF9jdCA9IG5ldyBUcmVlKCksIF9sZW4gPSBuZXcgVWludDhBcnJheSgzMjApLCBfb2ZmcyA9IG5ldyBVaW50MTZBcnJheSgxNik7CmZ1bmN0aW9uIF9iYmIoYml0cywgYmFzZSwgZGVsdGEsIGZpcnN0KSB7IHZhciBpLCBzOyBmb3IgKGkgPSAwOyBpIDwgZGVsdGE7ICsraSkgYml0c1tpXSA9IDA7IGZvciAoaSA9IDA7IGkgPCAzMCAtIGRlbHRhOyArK2kpIGJpdHNbaSArIGRlbHRhXSA9IGkgLyBkZWx0YSB8IDA7IGZvciAocyA9IGZpcnN0LCBpID0gMDsgaSA8IDMwOyArK2kpIHsgYmFzZVtpXSA9IHM7IHMgKz0gMSA8PCBiaXRzW2ldOyB9IH0KZnVuY3Rpb24gX2JmdChsdCwgZHQpIHsgdmFyIGk7IGZvciAoaSA9IDA7IGkgPCA3OyArK2kpIGx0LnRhYmxlW2ldID0gMDsgbHQudGFibGVbN10gPSAyNDsgbHQudGFibGVbOF0gPSAxNTI7IGx0LnRhYmxlWzldID0gMTEyOyBmb3IgKGkgPSAwOyBpIDwgMjQ7ICsraSkgbHQudHJhbnNbaV0gPSAyNTYgKyBpOyBmb3IgKGkgPSAwOyBpIDwgMTQ0OyArK2kpIGx0LnRyYW5zWzI0ICsgaV0gPSBpOyBmb3IgKGkgPSAwOyBpIDwgODsgKytpKSBsdC50cmFuc1syNCArIDE0NCArIGldID0gMjgwICsgaTsgZm9yIChpID0gMDsgaSA8IDExMjsgKytpKSBsdC50cmFuc1syNCArIDE0NCArIDggKyBpXSA9IDE0NCArIGk7IGZvciAoaSA9IDA7IGkgPCA1OyArK2kpIGR0LnRhYmxlW2ldID0gMDsgZHQudGFibGVbNV0gPSAzMjsgZm9yIChpID0gMDsgaSA8IDMyOyArK2kpIGR0LnRyYW5zW2ldID0gaTsgfQpmdW5jdGlvbiBfYnQodCwgbCwgb2ZmLCBudW0pIHsgdmFyIGksIHM7IGZvciAoaSA9IDA7IGkgPCAxNjsgKytpKSB0LnRhYmxlW2ldID0gMDsgZm9yIChpID0gMDsgaSA8IG51bTsgKytpKSB0LnRhYmxlW2xbb2ZmICsgaV1dKys7IHQudGFibGVbMF0gPSAwOyBmb3IgKHMgPSAwLCBpID0gMDsgaSA8IDE2OyArK2kpIHsgX29mZnNbaV0gPSBzOyBzICs9IHQudGFibGVbaV07IH0gZm9yIChpID0gMDsgaSA8IG51bTsgKytpKSB7IGlmIChsW29mZiArIGldKSB0LnRyYW5zW19vZmZzW2xbb2ZmICsgaV1dKytdID0gaTsgfSB9CmZ1bmN0aW9uIF9nYihkKSB7IGlmICghZC5iaXRjb3VudC0tKSB7IGQudCA9IGQuc1tkLmkrK107IGQuYml0Y291bnQgPSA3OyB9IHZhciBiID0gZC50ICYgMTsgZC50ID4+Pj0gMTsgcmV0dXJuIGI7IH0KZnVuY3Rpb24gX3JiKGQsIG51bSwgYmFzZSkgeyBpZiAoIW51bSkgcmV0dXJuIGJhc2U7IHdoaWxlIChkLmJpdGNvdW50IDwgMjQpIHsgZC50IHw9IGQuc1tkLmkrK10gPDwgZC5iaXRjb3VudDsgZC5iaXRjb3VudCArPSA4OyB9IHZhciB2ID0gZC50ICYgKDB4ZmZmZiA+Pj4gKDE2IC0gbnVtKSk7IGQudCA+Pj49IG51bTsgZC5iaXRjb3VudCAtPSBudW07IHJldHVybiB2ICsgYmFzZTsgfQpmdW5jdGlvbiBfZHN5KGQsIHQpIHsgd2hpbGUgKGQuYml0Y291bnQgPCAyNCkgeyBkLnQgfD0gZC5zW2QuaSsrXSA8PCBkLmJpdGNvdW50OyBkLmJpdGNvdW50ICs9IDg7IH0gdmFyIHN1bSA9IDAsIGN1ciA9IDAsIGxlbiA9IDAsIHRhZyA9IGQudDsgZG8geyBjdXIgPSAyICogY3VyICsgKHRhZyAmIDEpOyB0YWcgPj4+PSAxOyArK2xlbjsgc3VtICs9IHQudGFibGVbbGVuXTsgY3VyIC09IHQudGFibGVbbGVuXTsgfSB3aGlsZSAoY3VyID49IDApOyBkLnQgPSB0YWc7IGQuYml0Y291bnQgLT0gbGVuOyByZXR1cm4gdC50cmFuc1tzdW0gKyBjdXJdOyB9CmZ1bmN0aW9uIF9kdHIoZCwgbHQsIGR0KSB7IHZhciBobGl0LCBoZGlzdCwgaGNsZW4sIGksIG51bSwgbGVuZ3RoOyBobGl0ID0gX3JiKGQsIDUsIDI1Nyk7IGhkaXN0ID0gX3JiKGQsIDUsIDEpOyBoY2xlbiA9IF9yYihkLCA0LCA0KTsgZm9yIChpID0gMDsgaSA8IDE5OyArK2kpIF9sZW5baV0gPSAwOyBmb3IgKGkgPSAwOyBpIDwgaGNsZW47ICsraSkgX2xlbltfY2xjW2ldXSA9IF9yYihkLCAzLCAwKTsgX2J0KF9jdCwgX2xlbiwgMCwgMTkpOyBmb3IgKG51bSA9IDA7IG51bSA8IGhsaXQgKyBoZGlzdDspIHsgdmFyIHN5bSA9IF9kc3koZCwgX2N0KTsgc3dpdGNoIChzeW0pIHsgY2FzZSAxNjogdmFyIHAgPSBfbGVuW251bSAtIDFdOyBmb3IgKGxlbmd0aCA9IF9yYihkLCAyLCAzKTsgbGVuZ3RoOyAtLWxlbmd0aCkgX2xlbltudW0rK10gPSBwOyBicmVhazsgY2FzZSAxNzogZm9yIChsZW5ndGggPSBfcmIoZCwgMywgMyk7IGxlbmd0aDsgLS1sZW5ndGgpIF9sZW5bbnVtKytdID0gMDsgYnJlYWs7IGNhc2UgMTg6IGZvciAobGVuZ3RoID0gX3JiKGQsIDcsIDExKTsgbGVuZ3RoOyAtLWxlbmd0aCkgX2xlbltudW0rK10gPSAwOyBicmVhazsgZGVmYXVsdDogX2xlbltudW0rK10gPSBzeW07IH0gfSBfYnQobHQsIF9sZW4sIDAsIGhsaXQpOyBfYnQoZHQsIF9sZW4sIGhsaXQsIGhkaXN0KTsgfQpmdW5jdGlvbiBfaWIoZCwgbHQsIGR0KSB7IHdoaWxlICgxKSB7IHZhciBzeW0gPSBfZHN5KGQsIGx0KTsgaWYgKHN5bSA9PT0gMjU2KSByZXR1cm47IGlmIChzeW0gPCAyNTYpIGQuZGVzdFtkLmRlc3RMZW4rK10gPSBzeW07IGVsc2UgeyB2YXIgbGVuZ3RoLCBkaXN0LCBvLCBpOyBzeW0gLT0gMjU3OyBsZW5ndGggPSBfcmIoZCwgX2xiaXRzW3N5bV0sIF9sYmFzZVtzeW1dKTsgZGlzdCA9IF9kc3koZCwgZHQpOyBvID0gZC5kZXN0TGVuIC0gX3JiKGQsIF9kYml0c1tkaXN0XSwgX2RiYXNlW2Rpc3RdKTsgZm9yIChpID0gbzsgaSA8IG8gKyBsZW5ndGg7ICsraSkgZC5kZXN0W2QuZGVzdExlbisrXSA9IGQuZGVzdFtpXTsgfSB9IH0KZnVuY3Rpb24gX2l1KGQpIHsgdmFyIGxlbmd0aCwgaW52LCBpOyB3aGlsZSAoZC5iaXRjb3VudCA+IDgpIHsgZC5pLS07IGQuYml0Y291bnQgLT0gODsgfSBsZW5ndGggPSBkLnNbZC5pICsgMV07IGxlbmd0aCA9IDI1NiAqIGxlbmd0aCArIGQuc1tkLmldOyBpbnYgPSBkLnNbZC5pICsgM107IGludiA9IDI1NiAqIGludiArIGQuc1tkLmkgKyAyXTsgaWYgKGxlbmd0aCAhPT0gKH5pbnYgJiAweGZmZmYpKSB0aHJvdyBuZXcgRXJyb3IoJ2xlbicpOyBkLmkgKz0gNDsgZm9yIChpID0gbGVuZ3RoOyBpOyAtLWkpIGQuZGVzdFtkLmRlc3RMZW4rK10gPSBkLnNbZC5pKytdOyBkLmJpdGNvdW50ID0gMDsgfQpmdW5jdGlvbiBpbmZsYXRlUmF3KHNyYywgZGVzdCkgeyB2YXIgZCA9IG5ldyBJRGF0YShzcmMsIGRlc3QpLCBiZiwgYnQ7IGRvIHsgYmYgPSBfZ2IoZCk7IGJ0ID0gX3JiKGQsIDIsIDApOyBpZiAoYnQgPT09IDApIF9pdShkKTsgZWxzZSBpZiAoYnQgPT09IDEpIF9pYihkLCBfc2wsIF9zZCk7IGVsc2UgaWYgKGJ0ID09PSAyKSB7IF9kdHIoZCwgZC5sdHJlZSwgZC5kdHJlZSk7IF9pYihkLCBkLmx0cmVlLCBkLmR0cmVlKTsgfSBlbHNlIHRocm93IG5ldyBFcnJvcignYnR5cGUnKTsgfSB3aGlsZSAoIWJmKTsgcmV0dXJuIGQuZGVzdC5zdWJhcnJheSgwLCBkLmRlc3RMZW4pOyB9Cl9iZnQoX3NsLCBfc2QpOyBfYmJiKF9sYml0cywgX2xiYXNlLCA0LCAzKTsgX2JiYihfZGJpdHMsIF9kYmFzZSwgMiwgMSk7IF9sYml0c1syOF0gPSAwOyBfbGJhc2VbMjhdID0gMjU4OwpmdW5jdGlvbiBndW56aXAoYikgewogIGlmIChiLmxlbmd0aCA8IDE4IHx8IGJbMF0gIT09IDB4MWYgfHwgYlsxXSAhPT0gMHg4YikgdGhyb3cgbmV3IEVycm9yKCdub3QgZ3ppcCcpOwogIHZhciBmbGcgPSBiWzNdLCBvZmYgPSAxMDsKICBpZiAoZmxnICYgNCkgb2ZmICs9IDIgKyBiW29mZl0gKyAoYltvZmYgKyAxXSA8PCA4KTsKICBpZiAoZmxnICYgOCkgeyB3aGlsZSAoYltvZmYrK10gIT09IDApOyB9CiAgaWYgKGZsZyAmIDE2KSB7IHdoaWxlIChiW29mZisrXSAhPT0gMCk7IH0KICBpZiAoZmxnICYgMikgb2ZmICs9IDI7CiAgdmFyIGlzaXplID0gKGJbYi5sZW5ndGggLSA0XSB8IChiW2IubGVuZ3RoIC0gM10gPDwgOCkgfCAoYltiLmxlbmd0aCAtIDJdIDw8IDE2KSB8IChiW2IubGVuZ3RoIC0gMV0gPDwgMjQpKSA+Pj4gMDsKICByZXR1cm4gaW5mbGF0ZVJhdyhiLnN1YmFycmF5KG9mZiksIG5ldyBVaW50OEFycmF5KGlzaXplIHx8IGIubGVuZ3RoICogMjApKTsKfQpmdW5jdGlvbiBsb29rc1RleHQoYikgeyBjb25zdCBuID0gTWF0aC5taW4oYi5sZW5ndGgsIDY0KTsgaWYgKCFuKSByZXR1cm4gZmFsc2U7IGxldCBwID0gMDsgZm9yIChsZXQgaSA9IDA7IGkgPCBuOyBpKyspIHsgY29uc3QgYyA9IGJbaV07IGlmIChjID09PSA5IHx8IGMgPT09IDEwIHx8IGMgPT09IDEzIHx8IChjID49IDMyICYmIGMgPCAxMjcpKSBwKys7IH0gcmV0dXJuIHAgLyBuID4gMC44NTsgfQpmdW5jdGlvbiB0cygpIHsgcmV0dXJuIG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKS5zbGljZSgxMSwgMjMpOyB9CgovLyA9PT09PT09PT09PT09PT09PT09PT0gSFRUUCBwYXJzaW5nID09PT09PT09PT09PT09PT09PT09PQpmdW5jdGlvbiBkZWNodW5rKGJvZHkpIHsKICBjb25zdCBvdXQgPSBbXTsgbGV0IGkgPSAwOwogIHdoaWxlIChpIDwgYm9keS5sZW5ndGgpIHsKICAgIGNvbnN0IGVvbCA9IGZpbmRTZXEoYm9keSwgQ1JMRiwgaSk7IGlmIChlb2wgPCAwKSBicmVhazsKICAgIGNvbnN0IHNpemVTdHIgPSB1dGY4KGJvZHkuc2xpY2UoaSwgZW9sKSkuc3BsaXQoJzsnKVswXS50cmltKCk7CiAgICBjb25zdCBzaXplID0gcGFyc2VJbnQoc2l6ZVN0ciwgMTYpOwogICAgaWYgKGlzTmFOKHNpemUpKSB7IG91dC5wdXNoKGJvZHkuc2xpY2UoaSkpOyBicmVhazsgfQogICAgaSA9IGVvbCArIDI7CiAgICBpZiAoc2l6ZSA9PT0gMCkgYnJlYWs7CiAgICBvdXQucHVzaChib2R5LnNsaWNlKGksIGkgKyBzaXplKSk7CiAgICBpICs9IHNpemUgKyAyOwogIH0KICByZXR1cm4gY29uY2F0KG91dCk7Cn0KZnVuY3Rpb24gZm9ybWF0Qm9keShoZWFkZXJzLCBib2R5KSB7CiAgaWYgKGJvZHkubGVuZ3RoID09PSAwKSByZXR1cm4gJyc7CiAgY29uc3QgY2UgPSAoaGVhZGVyc1snY29udGVudC1lbmNvZGluZyddIHx8ICcnKS50b0xvd2VyQ2FzZSgpOwogIGxldCBub3RlID0gJyc7CiAgaWYgKGNlLmluY2x1ZGVzKCdnemlwJykgfHwgaXNHemlwKGJvZHkpKSB7CiAgICB0cnkgeyBjb25zdCB6ID0gYm9keS5sZW5ndGg7IGJvZHkgPSBndW56aXAoYm9keSk7IG5vdGUgPSBgW2d1bnppcHBlZCAke3p9IC0+ICR7Ym9keS5sZW5ndGh9IGJ5dGVzXVxuYDsgfQogICAgY2F0Y2ggKGUpIHsgbGV0IHMgPSBgW2d6aXAgYm9keSwgJHtib2R5Lmxlbmd0aH0gYnl0ZXMg4oCUIGluZmxhdGUgZmFpbGVkOiAke2UubWVzc2FnZX1dYDsgaWYgKEhFWERVTVBfQklOQVJZKSBzICs9ICdcbicgKyBoZXhkdW1wKGJvZHkuYnVmZmVyLCB7IGxlbmd0aDogTWF0aC5taW4oYm9keS5sZW5ndGgsIDEyOCksIGFuc2k6IGZhbHNlIH0pOyByZXR1cm4gczsgfQogIH0KICBpZiAoIWxvb2tzVGV4dChib2R5KSkgeyBsZXQgcyA9IG5vdGUgKyBgW2JpbmFyeSBib2R5LCAke2JvZHkubGVuZ3RofSBieXRlc11gOyBpZiAoSEVYRFVNUF9CSU5BUlkpIHMgKz0gJ1xuJyArIGhleGR1bXAoYm9keS5idWZmZXIsIHsgbGVuZ3RoOiBNYXRoLm1pbihib2R5Lmxlbmd0aCwgMjU2KSwgYW5zaTogZmFsc2UgfSk7IHJldHVybiBzOyB9CiAgY29uc3QgdGV4dCA9IHV0ZjgoYm9keSk7CiAgY29uc3QgY3QgPSAoaGVhZGVyc1snY29udGVudC10eXBlJ10gfHwgJycpLnRvTG93ZXJDYXNlKCk7CiAgY29uc3QgdHJpbW1lZCA9IHRleHQudHJpbSgpOwogIGlmIChQUkVUVFlfSlNPTiAmJiAoY3QuaW5jbHVkZXMoJ2pzb24nKSB8fCB0cmltbWVkLnN0YXJ0c1dpdGgoJ3snKSB8fCB0cmltbWVkLnN0YXJ0c1dpdGgoJ1snKSkpIHsKICAgIHRyeSB7IHJldHVybiBub3RlICsgSlNPTi5zdHJpbmdpZnkoSlNPTi5wYXJzZSh0cmltbWVkKSwgbnVsbCwgMik7IH0gY2F0Y2ggKGUpIHt9CiAgfQogIHJldHVybiBub3RlICsgdGV4dDsKfQpmdW5jdGlvbiBmb3JtYXRNZXNzYWdlKGJ5dGVzKSB7CiAgY29uc3QgaGRyRW5kID0gZmluZFNlcShieXRlcywgQ1JMRjIsIDApOwogIGxldCBoZWFkQmxvY2ssIGJvZHk7CiAgaWYgKGhkckVuZCA8IDApIHsgaGVhZEJsb2NrID0gdXRmOChieXRlcykucmVwbGFjZSgvXDArJC8sICcnKTsgYm9keSA9IG5ldyBVaW50OEFycmF5KDApOyB9CiAgZWxzZSB7IGhlYWRCbG9jayA9IHV0ZjgoYnl0ZXMuc2xpY2UoMCwgaGRyRW5kKSk7IGJvZHkgPSBieXRlcy5zbGljZShoZHJFbmQgKyA0KTsgfQogIGNvbnN0IGxpbmVzID0gaGVhZEJsb2NrLnNwbGl0KCdcclxuJyk7CiAgY29uc3QgaGVhZGVycyA9IHt9OwogIGZvciAobGV0IGsgPSAxOyBrIDwgbGluZXMubGVuZ3RoOyBrKyspIHsgY29uc3QgYyA9IGxpbmVzW2tdLmluZGV4T2YoJzonKTsgaWYgKGMgPiAwKSBoZWFkZXJzW2xpbmVzW2tdLnNsaWNlKDAsIGMpLnRyaW0oKS50b0xvd2VyQ2FzZSgpXSA9IGxpbmVzW2tdLnNsaWNlKGMgKyAxKS50cmltKCk7IH0KICBpZiAoKGhlYWRlcnNbJ3RyYW5zZmVyLWVuY29kaW5nJ10gfHwgJycpLnRvTG93ZXJDYXNlKCkuaW5jbHVkZXMoJ2NodW5rZWQnKSkgYm9keSA9IGRlY2h1bmsoYm9keSk7CiAgcmV0dXJuIHsgc3RhcnRMaW5lOiBsaW5lc1swXSB8fCAnJywgaGVhZEJsb2NrLCBib2R5U3RyOiBmb3JtYXRCb2R5KGhlYWRlcnMsIGJvZHkpLCBob3N0OiBoZWFkZXJzWydob3N0J10gfTsKfQoKLy8gPT09PT09PT09PT09PT09PT09PT09IHBlci1jb25uZWN0aW9uIHJlYXNzZW1ibHkgKyBzY29wZSBnYXRpbmcgPT09PT09PT09PT09PT09PT09PT09CmNvbnN0IHN0cmVhbXMgPSB7fTsgICAvLyBgJHtzc2x9fFRYfFJYYCAtPiB7IGNodW5rcywgdGltZXIgfQpjb25zdCBjb25uSG9zdCA9IHt9OyAgLy8gc3NsIC0+IGhvc3QgKGxlYXJuZWQgZnJvbSB0aGUgcmVxdWVzdCBvbiB0aGF0IGNvbm5lY3Rpb24pCgpmdW5jdGlvbiBmbHVzaChzc2xLZXksIGRpcikgewogIGNvbnN0IGtleSA9IHNzbEtleSArICd8JyArIGRpcjsgY29uc3QgcyA9IHN0cmVhbXNba2V5XTsKICBpZiAoIXMgfHwgcy5jaHVua3MubGVuZ3RoID09PSAwKSByZXR1cm47CiAgaWYgKHMudGltZXIpIHsgY2xlYXJUaW1lb3V0KHMudGltZXIpOyBzLnRpbWVyID0gbnVsbDsgfQogIGNvbnN0IGJ5dGVzID0gY29uY2F0KHMuY2h1bmtzKTsgcy5jaHVua3MgPSBbXTsKCiAgY29uc3QgbSA9IGZvcm1hdE1lc3NhZ2UoYnl0ZXMpOwogIGxldCBob3N0OwogIGlmIChkaXIgPT09ICdUWCcpIHsgaG9zdCA9IG0uaG9zdDsgaWYgKGhvc3QpIGNvbm5Ib3N0W3NzbEtleV0gPSBob3N0OyB9CiAgZWxzZSB7IGhvc3QgPSBjb25uSG9zdFtzc2xLZXldOyB9CgogIGlmICghc2hvdWxkU2hvdyhob3N0KSkgcmV0dXJuOyAvLyBvdXQgb2Ygc2NvcGUgLT4gc2lsZW50bHkgZHJvcAoKICBsZXQgYmFubmVyOwogIGlmIChkaXIgPT09ICdUWCcpIHsKICAgIGJhbm5lciA9IGNvbChDLmJvbGQgKyBDLmN5YW4sICfilrYgUkVRVUVTVCAnKSArICcgICcgKyBjb2woQy5jeWFuLCBtLnN0YXJ0TGluZSk7CiAgfSBlbHNlIHsKICAgIGNvbnN0IGNvZGUgPSBwYXJzZUludCgobS5zdGFydExpbmUubWF0Y2goL1xzKFxkezN9KVxzLykgfHwgW10pWzFdLCAxMCk7CiAgICBjb25zdCBzYyA9IGNvZGUgPj0gNTAwID8gQy5yZWQgOiBjb2RlID49IDQwMCA/IEMucmVkIDogY29kZSA+PSAyMDAgJiYgY29kZSA8IDMwMCA/IEMuZ3JlZW4gOiBDLnllbGxvdzsKICAgIGJhbm5lciA9IGNvbChDLmJvbGQgKyBzYywgJ+KXgCBSRVNQT05TRScpICsgJyAgJyArIGNvbChzYywgbS5zdGFydExpbmUpOwogIH0KICBjb25zb2xlLmxvZygnXG4nICsgYmFubmVyKTsKICBjb25zb2xlLmxvZyhjb2woQy5kaW0sIGAgICR7aG9zdCB8fCAnPyd9ICBjb25uPSR7c3NsS2V5LnNsaWNlKC02KX0gICR7dHMoKX0gICR7Ynl0ZXMubGVuZ3RofUJgKSk7CiAgY29uc29sZS5sb2coY29sKEMuZGltLCAn4pSAJy5yZXBlYXQoNjApKSk7CiAgY29uc29sZS5sb2cobS5oZWFkQmxvY2spOwogIGlmIChtLmJvZHlTdHIpIHsgY29uc29sZS5sb2coJycpOyBjb25zb2xlLmxvZyhtLmJvZHlTdHIpOyB9CiAgY29uc29sZS5sb2coJycpOwp9CgpmdW5jdGlvbiBmZWVkKHNzbCwgZGlyLCBidWYsIGxlbikgewogIGlmIChsZW4gPD0gMCkgcmV0dXJuOwogIGNvbnN0IHNzbEtleSA9IHNzbC50b1N0cmluZygpOwogIGZsdXNoKHNzbEtleSwgZGlyID09PSAnVFgnID8gJ1JYJyA6ICdUWCcpOyAvLyBkaXJlY3Rpb24gc3dpdGNoID0+IG90aGVyIHNpZGUgY29tcGxldGUKICBjb25zdCBrZXkgPSBzc2xLZXkgKyAnfCcgKyBkaXI7CiAgaWYgKCFzdHJlYW1zW2tleV0pIHN0cmVhbXNba2V5XSA9IHsgY2h1bmtzOiBbXSwgdGltZXI6IG51bGwgfTsKICBjb25zdCBzID0gc3RyZWFtc1trZXldOwogIHMuY2h1bmtzLnB1c2gobmV3IFVpbnQ4QXJyYXkoYnVmLnJlYWRCeXRlQXJyYXkobGVuKSkpOwogIGlmIChzLnRpbWVyKSBjbGVhclRpbWVvdXQocy50aW1lcik7CiAgcy50aW1lciA9IHNldFRpbWVvdXQoKCkgPT4gZmx1c2goc3NsS2V5LCBkaXIpLCBGTFVTSF9JRExFX01TKTsKfQoKLy8gPT09PT09PT09PT09PT09PT09PT09IGhvb2tzID09PT09PT09PT09PT09PT09PT09PQovLyBTU0xfd3JpdGU6IHJlcXVlc3QgcGxhaW50ZXh0IGlzIGluIHRoZSBidWZmZXIgb24gRU5URVIgKGxlbiA9IGFyZzIpLgovLyBTU0xfcmVhZCA6IHJlc3BvbnNlIHBsYWludGV4dCBpcyBpbiB0aGUgYnVmZmVyIG9uIExFQVZFIChsZW4gPSByZXR1cm4gdmFsdWUpLgpmdW5jdGlvbiBpbnN0YWxsKGJhc2UpIHsKICBJbnRlcmNlcHRvci5hdHRhY2goYmFzZS5hZGQoU1NMX1dSSVRFX09GRiksIHsKICAgIG9uRW50ZXIoYSkgeyBmZWVkKGFbMF0sICdUWCcsIGFbMV0sIGFbMl0udG9JbnQzMigpKTsgfQogIH0pOwogIEludGVyY2VwdG9yLmF0dGFjaChiYXNlLmFkZChTU0xfUkVBRF9PRkYpLCB7CiAgICBvbkVudGVyKGEpIHsgdGhpcy5zc2wgPSBhWzBdOyB0aGlzLmJ1ZiA9IGFbMV07IH0sCiAgICBvbkxlYXZlKHIpIHsgY29uc3QgbiA9IHIudG9JbnQzMigpOyBpZiAobiA+IDApIGZlZWQodGhpcy5zc2wsICdSWCcsIHRoaXMuYnVmLCBuKTsgfQogIH0pOwogIGNvbnNvbGUubG9nKCdbK10gZmx1dHRlci1odHRwLW1vbml0b3Igb24gbGliZmx1dHRlci5zbyBAICcgKyBiYXNlKTsKICBjb25zb2xlLmxvZygnICAgIFNTTF93cml0ZSArMHgnICsgU1NMX1dSSVRFX09GRi50b1N0cmluZygxNikgKyAnIChyZXEpICAgU1NMX3JlYWQgKzB4JyArIFNTTF9SRUFEX09GRi50b1N0cmluZygxNikgKyAnIChyZXNwKScpOwogIGNvbnNvbGUubG9nKCcgICAgUkVQTDogYWRkU2NvcGUoaCkgLyByZW1vdmVTY29wZShoKSAvIGNsZWFyU2NvcGUoKSAvIGxpc3RTY29wZSgpIC8gc2NvcGVPbmx5KHRydWV8ZmFsc2UpJyk7CiAgbGlzdFNjb3BlKCk7CiAgY29uc29sZS5sb2coJ1sqXSBEcml2ZSB0aGUgYXBwIG5vdy4uLicpOwp9CmZ1bmN0aW9uIGZpbmRMaWIoKSB7CiAgdHJ5IHsgaWYgKHR5cGVvZiBNb2R1bGUuZ2V0QmFzZUFkZHJlc3MgPT09ICdmdW5jdGlvbicpIHsgY29uc3QgYSA9IE1vZHVsZS5nZXRCYXNlQWRkcmVzcygnbGliZmx1dHRlci5zbycpOyBpZiAoYSkgcmV0dXJuIGE7IH0gfSBjYXRjaCAoZSkge30KICB0cnkgeyBjb25zdCBtID0gUHJvY2Vzcy5maW5kTW9kdWxlQnlOYW1lKCdsaWJmbHV0dGVyLnNvJyk7IGlmIChtKSByZXR1cm4gbS5iYXNlOyB9IGNhdGNoIChlKSB7fQogIHRyeSB7IGlmICh0eXBlb2YgTW9kdWxlLmZpbmRCYXNlQWRkcmVzcyA9PT0gJ2Z1bmN0aW9uJykgeyBjb25zdCBhID0gTW9kdWxlLmZpbmRCYXNlQWRkcmVzcygnbGliZmx1dHRlci5zbycpOyBpZiAoYSkgcmV0dXJuIGE7IH0gfSBjYXRjaCAoZSkge30KICByZXR1cm4gbnVsbDsKfQooZnVuY3Rpb24gd2FpdCgpIHsgY29uc3QgbCA9IGZpbmRMaWIoKTsgaWYgKGwgPT09IG51bGwpIHsgc2V0VGltZW91dCh3YWl0LCAzMDApOyByZXR1cm47IH0gaW5zdGFsbChsKTsgfSkoKTsK"

def load_template(template_arg):
    if template_arg:
        return open(template_arg, "r", encoding="utf-8").read()
    if EMBEDDED_TEMPLATE_B64 == "__EMBED__":
        sys.exit("No embedded template. Pass --template flutter-http-monitor.js, or "
                 "run --embed flutter-http-monitor.js to bake it in.")
    return base64.b64decode(EMBEDDED_TEMPLATE_B64).decode("utf-8")

def embed_template(js_path):
    """Bake a template .js into this script's EMBEDDED_TEMPLATE_B64 (dev helper)."""
    b64 = base64.b64encode(open(js_path, "rb").read()).decode("ascii")
    me = os.path.abspath(__file__)
    src = open(me, "r", encoding="utf-8").read()
    src2, n = re.subn(r'EMBEDDED_TEMPLATE_B64 = "[^"]*"',
                      'EMBEDDED_TEMPLATE_B64 = "%s"' % b64, src, count=1)
    if not n:
        sys.exit("Could not find EMBEDDED_TEMPLATE_B64 to update.")
    open(me, "w", encoding="utf-8").write(src2)
    print(f"[+] embedded {js_path} ({len(b64)} b64 chars) into {os.path.basename(me)}")

# ----------------- input loading (.so or .apk) -----------------
def load_libflutter(path):
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            cands = [n for n in z.namelist() if n.endswith("libflutter.so")]
            arm64 = [n for n in cands if "arm64-v8a" in n] or cands
            if not arm64:
                sys.exit("No libflutter.so found inside the APK.")
            print(f"[*] APK: extracting {arm64[0]}")
            return io.BytesIO(z.read(arm64[0]))
    return open(path, "rb")

# ----------------- helpers -----------------
def find_anchor_vaddrs(elf, needle):
    """vaddrs of NUL-terminated strings (in alloc PROGBITS) that contain `needle`."""
    out = []
    for sec in elf.iter_sections():
        if sec["sh_type"] != "SHT_PROGBITS" or not (sec["sh_flags"] & 0x2):
            continue
        data = sec.data(); base = sec["sh_addr"]; start = 0
        for j, b in enumerate(data):
            if b == 0:
                if start < j and needle in data[start:j]:
                    out.append(base + start)
                start = j + 1
    return out

def detect_version(raw):
    m = re.search(rb'(\d+\.\d+\.\d+)\s+\(stable\)\s+\([^)]*\)\s+on\s+"[^"]*"', raw)
    if m:
        return m.group(0).decode("latin1").strip()
    m = re.search(rb"(\d+\.\d+\.\d+)\s+\(stable\)", raw)
    if m:
        return m.group(0).decode("latin1").strip()
    m = re.search(rb"Dart VM version: (\d+\.\d+\.\d+)", raw)
    return m.group(1).decode() if m else "unknown"

# ----------------- core analysis -----------------
class Analyzer:
    def __init__(self, elf):
        self.elf = elf
        text = elf.get_section_by_name(".text")
        self.tdata = text.data(); self.tva = text["sh_addr"]
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); self.md.skipdata = True

    def sweep(self, anchor_addrs):
        """Lite pass: refs to anchor strings, BL edges, function starts."""
        re_adrp = re.compile(r"^(\w+), #?(0x[0-9a-f]+)$")
        re_add = re.compile(r"^(\w+), (\w+), #?(0x[0-9a-f]+|\d+)$")
        re_ldr = re.compile(r"^(\w+), \[(\w+),? ?#?(0x[0-9a-f]+|\d+)?\]?$")
        re_bl = re.compile(r"^#?(0x[0-9a-f]+)$")
        anchors = set(anchor_addrs)
        adrp = {}; refs = []; bl_edges = []; bl_targets = set()
        for addr, size, mn, op in self.md.disasm_lite(self.tdata, self.tva):
            if mn == "adrp":
                m = re_adrp.match(op)
                if m: adrp[m.group(1)] = int(m.group(2), 16)
            elif mn == "add":
                m = re_add.match(op)
                if m and m.group(2) in adrp:
                    imm = int(m.group(3), 16) if m.group(3).startswith("0x") else int(m.group(3))
                    t = adrp[m.group(2)] + imm
                    if t in anchors: refs.append(addr)
                    adrp.pop(m.group(1), None)
            elif mn == "ldr":
                m = re_ldr.match(op)
                if m and m.group(2) in adrp:
                    d = m.group(3)
                    imm = (int(d, 16) if d.startswith("0x") else int(d)) if d else 0
                    if adrp[m.group(2)] + imm in anchors: refs.append(addr)
            elif mn == "bl":
                m = re_bl.match(op)
                if m:
                    t = int(m.group(1), 16); bl_targets.add(t); bl_edges.append((addr, t))
        self.func_starts = sorted(bl_targets)
        return refs, bl_edges

    def enclosing(self, addr):
        i = bisect.bisect_right(self.func_starts, addr) - 1
        return self.func_starts[i] if i >= 0 else None

    def window(self, addr, count=64):
        off = addr - self.tva
        return list(self.md.disasm(self.tdata[off:off + count * 4], addr))

    def window_to_next(self, addr, cap=2000):
        i = bisect.bisect_right(self.func_starts, addr)
        end = self.func_starts[i] if i < len(self.func_starts) else addr + cap * 4
        n = min(end - addr, cap * 4)
        off = addr - self.tva
        return list(self.md.disasm(self.tdata[off:off + n], addr))

    @staticmethod
    def _bl_target(op):
        m = re.match(r"^#?(0x[0-9a-f]+)$", op)
        return int(m.group(1), 16) if m else None

    def caller_votes(self, filter_funcs):
        """Scan filter functions; classify each BL target by how its result is used:
           clamp >=0 (bic/csel-after-cmp)  => read-like ; sign-bit test => write-like."""
        read_v, write_v = Counter(), Counter()
        for ff in filter_funcs:
            ins = self.window_to_next(ff)
            for k, x in enumerate(ins):
                if x.mnemonic != "bl":
                    continue
                tgt = self._bl_target(x.op_str)
                if tgt is None:
                    continue
                for y in ins[k + 1:k + 6]:
                    m, op = y.mnemonic, y.op_str
                    if (m == "bic" and "asr #31" in op) or \
                       (m in ("csel", "csinc") and "wzr" in op):
                        read_v[tgt] += 1; break
                    if (m in ("tbz", "tbnz") and ("#0x1f" in op or "#31" in op)) or \
                       (m in ("cmp",) and re.search(r", #0$", op)):
                        write_v[tgt] += 1; break
        return read_v, write_v

    def fingerprint(self, addr):
        """Score how much `addr` looks like SSL_read/SSL_write; capture error helper."""
        ins = self.window(addr, 64)
        frame = 0; field_load = False; neg1 = False; helpers = []; blc = 0
        for k, x in enumerate(ins):
            m, op = x.mnemonic, x.op_str
            if k == 0 and m == "sub" and op.startswith("sp, sp"):
                mm = re.search(r"#(0x[0-9a-f]+|\d+)", op)
                if mm: frame = int(mm.group(1), 16) if mm.group(1).startswith("0x") else int(mm.group(1))
            if m == "ldr" and "[x0" in op and k < 14:
                field_load = True
            if m in ("mov", "movn") and ("-1" in op or "0xffffffff" in op):
                neg1 = True
            if m == "bl":
                blc += 1
                for back in (1, 2):
                    if k - back >= 0:
                        pm = ins[k - back]
                        mm = re.match(r"^w\d+, #?(0x[0-9a-f]+|\d+)$", pm.op_str) if pm.mnemonic == "mov" else None
                        if mm:
                            val = int(mm.group(1), 16) if mm.group(1).startswith("0x") else int(mm.group(1))
                            if 0x20 <= val <= 0x6000:
                                tm = re.match(r"^#?(0x[0-9a-f]+)$", op)
                                if tm: helpers.append((int(tm.group(1), 16), val))
                            break
            if m == "ret":
                break
        score = (2 if field_load else 0) + (3 if helpers else 0) + (1 if neg1 else 0)
        return dict(score=score, frame=frame, helpers=helpers, blc=blc,
                    field_load=field_load, neg1=neg1)

    def find(self):
        anchors = find_anchor_vaddrs(self.elf, ANCHOR_FILTER)
        if not anchors:
            sys.exit("Anchor 'secure_socket_filter.cc' not found — not a Flutter engine, or non-arm64 build.")
        refs, bl_edges = self.sweep(anchors)
        filter_funcs = set(f for f in (self.enclosing(a) for a in refs) if f)
        if not filter_funcs:
            sys.exit("Could not locate the Dart TLS filter functions.")

        # Primary signal: how the Dart filter consumes each callee's int result.
        # Empirically: result clamped to >=0 (bic asr#31) follows SSL_write;
        #              result sign-tested (tbz #31) follows SSL_read.
        clamp_v, sign_v = self.caller_votes(filter_funcs)

        def best(votes, other):
            """pick the SSL data fn from voted targets: prefer clear winner with SSL shape."""
            ranked = []
            for tgt, v in votes.items():
                fp = self.fingerprint(tgt)
                ranked.append((v - other.get(tgt, 0), fp["score"], tgt, fp))
            ranked.sort(reverse=True)
            return ranked[0] if ranked else None

        wb_, rb_ = best(clamp_v, sign_v), best(sign_v, clamp_v)
        if not rb_ or not wb_:
            sys.exit("Could not classify SSL_read/SSL_write from caller result-handling.")
        write, write_fp = wb_[2], wb_[3]
        read, read_fp = rb_[2], rb_[3]

        if read == write:  # tie-break by structure (write = bigger frame / handshake loop)
            cand = sorted(set(clamp_v) | set(sign_v),
                          key=lambda t: -self.fingerprint(t)["score"])[:2]
            if len(cand) >= 2:
                a, b = cand[0], cand[1]
                fa, fb = self.fingerprint(a), self.fingerprint(b)
                write, write_fp = (a, fa) if (fa["frame"], fa["blc"]) >= (fb["frame"], fb["blc"]) else (b, fb)
                read, read_fp = (b, fb) if write == a else (a, fa)

        wv, rv = clamp_v.get(write, 0), sign_v.get(read, 0)
        confidence = "high" if (rv > 0 and wv > 0 and read != write) else "medium"
        evidence = {
            "filter_funcs": sorted(filter_funcs),
            "read_votes": rv, "write_votes": wv,
            "read_fp": read_fp, "write_fp": write_fp,
        }
        return write, read, confidence, evidence

# ----------------- generation -----------------
def generate(template_text, write_off, read_off, version):
    js = template_text
    js, n1 = re.subn(r"const\s+SSL_WRITE_OFF\s*=\s*0x[0-9a-fA-F]+\s*;",
                     f"const SSL_WRITE_OFF = 0x{write_off:x};", js, count=1)
    js, n2 = re.subn(r"const\s+SSL_READ_OFF\s*=\s*0x[0-9a-fA-F]+\s*;",
                     f"const SSL_READ_OFF  = 0x{read_off:x};", js, count=1)
    if not (n1 and n2):
        sys.exit("Template missing SSL_WRITE_OFF / SSL_READ_OFF constants to patch.")
    banner = (f"// AUTO-GENERATED by flutter_http_monitor.py\n"
              f"// Flutter/engine: {version}\n"
              f"// SSL_write +0x{write_off:x}   SSL_read +0x{read_off:x}\n\n")
    return banner + js

# ----------------- main -----------------
def main():
    ap = argparse.ArgumentParser(description="Auto-find SSL_read/SSL_write in libflutter.so and emit a Frida monitor.")
    ap.add_argument("input", nargs="?", help="libflutter.so or an .apk")
    ap.add_argument("-o", "--output", help="output Frida JS (default: flutter-http-monitor.generated.js)")
    ap.add_argument("--template", default=None, help="external template JS (default: built-in embedded template)")
    ap.add_argument("--print-only", action="store_true", help="only print offsets; do not generate JS")
    ap.add_argument("--embed", metavar="TEMPLATE.js", help="(dev) bake a template JS into this script and exit")
    args = ap.parse_args()

    if args.embed:
        embed_template(args.embed)
        return
    if not args.input:
        ap.error("input (libflutter.so or .apk) is required")

    with load_libflutter(args.input) as f:
        raw = f.read(); f.seek(0)
        elf = ELFFile(f)
        if elf.get_machine_arch() != "AArch64":
            sys.exit(f"Only arm64 (AArch64) is supported; got {elf.get_machine_arch()}.")
        version = detect_version(raw)
        print(f"[*] Flutter/engine: {version}")
        write_off, read_off, conf, ev = Analyzer(elf).find()

    print(f"[+] SSL_write @ +0x{write_off:x}   (req,  read buffer on ENTER)")
    print(f"[+] SSL_read  @ +0x{read_off:x}   (resp, read buffer on LEAVE)")
    print(f"[+] confidence: {conf}   clamp-votes read={ev['read_votes']} write={ev['write_votes']}")
    print(f"    filter funcs: {', '.join(hex(f) for f in ev['filter_funcs'])}")
    if conf != "high":
        print("    [!] medium confidence — verify at runtime: a REQUEST block must show an")
        print("        outgoing 'GET/POST ... HTTP/1.1'. If req/resp look swapped, swap the offsets.")

    if args.print_only:
        return
    template_text = load_template(args.template)
    out = args.output or "flutter-http-monitor.generated.js"
    open(out, "w", encoding="utf-8").write(generate(template_text, write_off, read_off, version))
    print(f"[+] wrote {out}")
    print(f"    run:  frida -U -f <package> -l {out}")

if __name__ == "__main__":
    main()
