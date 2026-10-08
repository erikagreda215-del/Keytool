Keytool en Python
Simulador de la herramienta keytool de Java desarrollado en Python.

INTEGRANTES
Genesis
Erik

Requisitos
Python 3.10 o superior
pip
Instalación
Clona el repositorio:

git clone <URL_DEL_REPOSITORIO>
cd Keytool
Crea un entorno virtual:

Windows
py -m venv .venv
Activa el entorno virtual:

.\.venv\Scripts\Activate.ps1
Instala las dependencias:

python -m pip install -r requirements.txt
Dependencias
Las dependencias del proyecto están especificadas en requirements.txt:

cryptography==50.0.2
cffi==2.1.1
pycparser==3.0
No es necesario instalarlas manualmente si se ejecuta:

python -m pip install -r requirements.txt
Uso
Para generar un par de claves RSA:

python mykeytool.py --genkeypair
Para generar una solicitud de certificado (CSR):

python mykeytool.py --certreq
Archivos principales
mykeytool.py — programa principal.
crypto_utils.py — funciones criptográficas.
keystore.py — gestión del almacén de claves.
requirements.txt — dependencias del proyecto.
Notas
El proyecto utiliza RSA de 2048 bits y SHA-256 para la generación de solicitudes de certificado.