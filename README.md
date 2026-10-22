# 🔑 Keytool en Python

Simulador en línea de comandos de la herramienta **`keytool`** de Java, hecho en Python con la librería `cryptography`.

## 👥 Integrantes

- Erik Brayan Agreda Avila ([erikagreda215-del](https://github.com/erikagreda215-del))
- Genesis Andrea Silva Acosta ([genesisilaco-droid](https://github.com/genesisilaco-droid))

## ⚙️ Instalación

Requiere **Python 3.10** o superior.

```bash
git clone https://github.com/erikagreda215-del/Keytool.git
cd Keytool
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

La única dependencia directa es `cryptography` (`pip install cryptography`).

## 🗂️ Estructura

| Archivo | Contenido |
|---|---|
| `mykeytool.py` | Programa principal: comandos y preguntas al usuario. |
| `keystore.py` | Almacén: creación, cifrado, descifrado, validación y guardado. |
| `crypto_utils.py` | Criptografía: claves RSA, CSR y certificado autofirmado. |

Al usar el programa se crea `mykeytool.keystore` (el almacén), un archivo binario cifrado que no se sube al repositorio.

## 🚀 Uso

| Comando | Descripción |
|---|---|
| `python mykeytool.py --help` | Muestra los comandos disponibles. |
| `python mykeytool.py --genkeypair` | Genera un par de claves RSA 2048 y lo guarda en el almacén. |
| `python mykeytool.py --certreq` | Genera la solicitud de certificado `<alias>.csr` en formato PEM. |
| `python mykeytool.py --list` *(ampliación)* | Lista los alias del almacén. |
| `python mykeytool.py --delete` *(ampliación)* | Elimina un alias. |
| `python mykeytool.py --selfcert` *(ampliación)* | Genera un certificado autofirmado `<alias>.crt`. |

### Ejemplos

Las contraseñas no se ven al escribirlas; aquí aparecen como `******`.

```text
> python mykeytool.py --genkeypair
No existe almacén; se creará uno nuevo.
Contraseña del KeyStore (mín. 6 caracteres): ******
Repite la contraseña: ******
Alias: prueba
Datos del titular (Enter para dejar vacío):
  CN - Nombre y apellidos: Persona Prueba
  OU - Unidad organizativa: IT
  O - Organización: Ejemplo SA
  L - Ciudad: Barcelona
  ST - Provincia: Barcelona
  C - País (2 letras, ej. ES): es
Contraseña del alias 'prueba' (mín. 6 caracteres): ******
Repite la contraseña: ******
Par de claves RSA 2048 generado y guardado con el alias 'prueba'.

> python mykeytool.py --certreq
Contraseña del KeyStore: ******
Alias: prueba
Contraseña del alias 'prueba': ******
CSR generado en 'prueba.csr' (formato PEM).

> python mykeytool.py --list
Contraseña del KeyStore: ******
El almacén contiene 1 entrada(s).
  - prueba: C=ES,ST=Barcelona,L=Barcelona,O=Ejemplo SA,OU=IT,CN=Persona Prueba
```

Errores controlados:

```text
> python mykeytool.py --certreq
Contraseña del KeyStore: ******
Error: contraseña del almacén incorrecta (o el almacén ha sido manipulado).

> python mykeytool.py --genkeypair
Contraseña del KeyStore: ******
Alias: prueba
Error: el alias 'prueba' ya existe en el almacén.
```

## 🔐 Seguridad

- Claves **RSA de 2048 bits**; CSR y certificados firmados con **SHA-256** en formato **PEM**.
- El almacén se guarda **cifrado entero** con **AES-256-GCM**: al abrir el archivo no se puede leer ningún dato (ni alias, ni titulares, ni claves).
- La clave de cifrado se deriva de la contraseña del almacén con **PBKDF2-HMAC-SHA256** (200 000 iteraciones y sal aleatoria). La contraseña no se guarda en ningún sitio.
- AES-GCM detecta cualquier modificación del archivo: si alguien lo manipula, no se puede abrir.
- Además, cada clave privada va **cifrada** con la contraseña de su alias (doble protección, como en Java).
- Si el almacén falta o está dañado, se avisa sin que el programa falle.

Formato del archivo: `MYKS` (4 bytes) · sal (16 bytes) · nonce (12 bytes) · datos cifrados.

## 🧪 Matriz de pruebas

| # | Comando | Escenario | Resultado esperado | Resultado |
|---|---|---|---|---|
| 1 | `--help` | Mostrar la ayuda | Lista de comandos | ✅ |
| 2 | `--genkeypair` | Sin almacén previo | Crea el almacén y guarda la clave | ✅ |
| 3 | `--genkeypair` | Almacén existente | Añade el nuevo alias | ✅ |
| 4 | `--genkeypair` | Alias duplicado | Error: el alias ya existe | ✅ |
| 5 | `--genkeypair` | Alias vacío o país de más de 2 letras | Mensaje de error | ✅ |
| 6 | `--genkeypair` | Contraseña corta o que no coincide | La vuelve a pedir | ✅ |
| 7 | `--certreq` | Datos correctos | Genera `<alias>.csr` válido | ✅ |
| 8 | `--certreq` | Almacén inexistente | Error: no existe el almacén | ✅ |
| 9 | Todos | Contraseña del almacén incorrecta | Error: contraseña incorrecta | ✅ |
| 10 | `--certreq` / `--selfcert` | Contraseña del alias incorrecta | Error: contraseña incorrecta | ✅ |
| 11 | `--certreq` / `--delete` | Alias inexistente | Error: el alias no existe | ✅ |
| 12 | `--certreq` / `--selfcert` | El archivo ya existe | Pregunta antes de sobrescribir | ✅ |
| 13 | `--list` | Datos correctos | Muestra los alias | ✅ |
| 14 | `--delete` | Confirmar con `s` / responder `n` | Elimina / cancela | ✅ |
| 15 | `--selfcert` | Datos correctos / días no válidos | Genera `<alias>.crt` / mensaje de error | ✅ |
| 16 | Todos | `mykeytool.keystore` dañado | Error: almacén dañado | ✅ |
| 17 | Todos | `mykeytool.keystore` manipulado (un byte cambiado) | Error: contraseña incorrecta o almacén manipulado | ✅ |
| 18 | — | Abrir `mykeytool.keystore` con un editor | Contenido ilegible (binario cifrado) | ✅ |
