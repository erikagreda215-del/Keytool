# Plan de trabajo — Simulador de Java Keytool en Python

Práctica en parejas, evaluación **individual** (defensa presencial). Por eso:

- Cada integrante es **dueño** de unos módulos concretos y debe poder explicarlos a fondo.
- Ambos deben **entender todo el proyecto**: cada uno revisa el código del otro antes de fusionarlo.
- Los commits deben ser **representativos de ambos** (cuenta en la rúbrica, 10%).

| Rol | Integrante | Responsabilidad principal |
|-----|------------|---------------------------|
| **A** | Erik Brayan | CLI (`argparse`), KeyStore cifrado, comando `--genkeypair`, gestión de errores |
| **B** | _(compañero/a)_ | Criptografía RSA, Distinguished Name, comando `--certreq` (CSR PEM), pruebas |

---

## 1. Estructura del repositorio

```
Keytool/
├── mykeytool.py        # [A] Punto de entrada: argparse y despacho de comandos
├── keystore.py         # [A] Persistencia cifrada del almacén (cargar/guardar, alias)
├── errors.py           # [A] Excepciones propias (contraseña incorrecta, alias duplicado, almacén inexistente)
├── commands.py         # [A] genkeypair  /  [B] certreq  (cada uno su función)
├── crypto_utils.py     # [B] Generación RSA 2048, serialización de claves, construcción de CSR
├── prompts.py          # [B] Entrada interactiva: contraseñas (getpass), alias, datos del DN
├── tests/              # [A+B] Pruebas de cada módulo
├── requirements.txt    # Dependencias (cryptography)
├── README.md           # [A+B] Documentación de entrega
└── PLAN.md             # Este documento
```

---

## 2. Flujo de trabajo con Git

- Rama `main` siempre funcional. Nadie hace commit directo a `main` salvo este arranque.
- Una rama por tarea: `feature/<tarea>` (p. ej. `feature/keystore`, `feature/csr`).
- Al terminar: Pull Request en GitHub → el **otro** integrante lo revisa → merge.
- Mensajes de commit en español y con prefijo:
  - `feat:` funcionalidad nueva · `fix:` corrección · `docs:` documentación
  - `test:` pruebas · `refactor:` reorganización sin cambiar comportamiento · `chore:` configuración
- Cada uno hace commit **desde su propia cuenta de GitHub** (si no, no cuenta como suyo).

---

## 3. Commits planificados por sesión

### Sesión 1 — Análisis y diseño (hecho en este arranque)
| # | Autor | Commit |
|---|-------|--------|
| 1 | A | `chore: estructura inicial del proyecto y requirements` |
| 2 | A | `docs: plan de trabajo y reparto de tareas` |
| 3 | B | `docs: análisis de los comandos de Java keytool en el README` |

### Sesión 2 — CLI y generación RSA
| # | Autor | Rama | Commit |
|---|-------|------|--------|
| 4 | A | `feature/cli` | `feat: parser de argumentos con --help, --genkeypair y --certreq` |
| 5 | A | `feature/cli` | `feat: despacho de cada opción a su comando` |
| 6 | B | `feature/rsa` | `feat: generación de par de claves RSA de 2048 bits` |
| 7 | B | `feature/rsa` | `feat: solicitud interactiva de contraseña, alias y DN (CN, OU, O, L, ST, C)` |
| 8 | B | `feature/rsa` | `feat: construcción del Distinguished Name con x509.Name` |

### Sesión 3 — KeyStore cifrado y CSR
| # | Autor | Rama | Commit |
|---|-------|------|--------|
| 9  | A | `feature/keystore` | `feat: formato del archivo KeyStore y guardado/carga` |
| 10 | A | `feature/keystore` | `feat: cifrado del almacén con la contraseña (derivación de clave + cifrado simétrico)` |
| 11 | A | `feature/keystore` | `feat: clave privada de cada alias protegida con su propia contraseña` |
| 12 | A | `feature/genkeypair` | `feat: comando --genkeypair completo (RSA + guardado en almacén)` |
| 13 | B | `feature/csr` | `feat: generación del CSR firmado con la clave privada del alias` |
| 14 | B | `feature/csr` | `feat: comando --certreq exporta el archivo .csr en PEM` |

### Sesión 4 — Errores, pruebas y documentación
| # | Autor | Rama | Commit |
|---|-------|------|--------|
| 15 | A | `feature/errores` | `feat: excepciones propias del proyecto` |
| 16 | A | `feature/errores` | `fix: contraseña incorrecta del almacén o del alias sin trazas` |
| 17 | A | `feature/errores` | `fix: rechazo de alias duplicado en --genkeypair` |
| 18 | A | `feature/errores` | `fix: aviso de almacén inexistente o dañado` |
| 19 | B | `feature/tests` | `test: pruebas de generación RSA y CSR` |
| 20 | B | `feature/tests` | `test: pruebas de los casos de error` |
| 21 | B | `docs/readme` | `docs: guía de uso con ejemplos de consola` |
| 22 | A | `docs/readme` | `docs: instalación de dependencias y matriz de pruebas` |
| 23 | A+B | `main` | `chore: limpieza de código muerto antes de la entrega` |

### Ampliación (30% de la nota) — repartida a partes iguales
| # | Autor | Commit |
|---|-------|--------|
| 24 | A | `feat: comando --list para mostrar los alias del almacén` |
| 25 | A | `feat: comando --delete para eliminar un alias` |
| 26 | A | `feat: comando --storepasswd para cambiar la contraseña del almacén` |
| 27 | B | `feat: comando --selfcert para generar un certificado autofirmado` |
| 28 | B | `feat: comando --exportcert para exportar el certificado en PEM` |
| 29 | B | `feat: comando --printcert para mostrar los datos de un certificado o CSR` |
| 30 | A+B | `feat: opción -keystore para elegir el archivo de almacén` |
| 31 | A+B | `docs: documentación de las ampliaciones en el README` |

> Las ampliaciones son una propuesta: se pueden cambiar, pero conviene que cada uno tenga
> el mismo número y dificultad parecida para que ambos puedan defenderlas.

---

## 4. Preparación de la defensa (Sesión 5)

Cada integrante debe saber explicar, **también del módulo del otro**:

- [ ] Cómo `argparse` interpreta las opciones y llama a cada comando.
- [ ] Qué es un par RSA, por qué 2048 bits y qué exponente público se usa.
- [ ] Qué contiene un Distinguished Name (CN, OU, O, L, ST, C).
- [ ] Qué es un CSR, qué datos lleva y por qué va firmado con la clave privada.
- [ ] Qué es el formato PEM.
- [ ] Cómo se cifra el KeyStore: derivación de la clave a partir de la contraseña, sal y algoritmo.
- [ ] Cómo se detecta una contraseña incorrecta, un alias duplicado y un almacén inexistente o dañado.
