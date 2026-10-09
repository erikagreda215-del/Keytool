# 🔑 Keytool en Python

> Simulador interactivo de la herramienta **`keytool`** de Java desarrollado en Python.

---

## 👥 Integrantes

* **Genesis**
* **Erik**

---

## 📋 Requisitos Previos

Asegúrate de contar con lo siguiente instalado en tu sistema:

* ![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white) **Python 3.10** o superior
* ![pip](https://img.shields.io/badge/pip-latest-blue?logo=pypi&logoColor=white) **pip** (gestor de paquetes de Python)

---

##  Instalación y Configuración

Sigue estos pasos para clonar e instalar el proyecto en Windows:

# 1. Clonar el repositorio

git clone [https://github.com/erikagreda215-del/Keytool.git](https://github.com/erikagreda215-del/Keytool.git)
cd Keytool

# 2. Crear y activar el entorno virtual


## Crear entorno virtual
py -m venv .venv

## Activar entorno virtual 
.\.venv\Scripts\Activate.ps1

# 3. Instalar dependencias

   python -m pip install -r requirements.txt

---
## 📦 DependenciasEl proyecto utiliza las siguientes librerías especificadas en requirements.txt

##  Uso

Generar un par de claves RSA

python mykeytool.py --genkeypair

Generar una solicitud de certificado (CSR)

python mykeytool.py --certreq

---

### El proyecto implementa algoritmos RSA de 2048 bits para la generación de claves.

### Utiliza SHA-256 para el firmado de las solicitudes de certificado (CSR)