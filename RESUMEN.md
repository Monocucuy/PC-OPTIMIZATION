# Resumen del proyecto: MatrixScan

Registro de todo lo que se construyó en esta sesión, cómo se tomaron las decisiones, qué se probó y qué falta.

---

## 1. Qué pediste

Un programa para tu PC que:

1. Escanee el disco en busca de basura y archivos que no usas.
2. Haga un análisis de seguridad enfocado en virus y procesos en segundo plano.
3. **Mida cuánto rendimiento te quitan** esos procesos.
4. Tenga un diseño bonito, tipo Matrix, en verde y con animaciones.

## 2. Decisiones que tomaste

| Pregunta | Tu respuesta | Qué implica |
|---|---|---|
| ¿Qué basura buscar? | Las 4 opciones | Temporales, cachés y papelera + archivos grandes sin abrir + duplicados + programas sin usar |
| ¿Qué hacer con lo encontrado? | **Solo reporte** | El programa **nunca borra nada**. Muestra la ruta, el tamaño y cómo limpiarlo a mano |
| ¿Análisis de seguridad? | VirusTotal si es gratis; si no, Defender + heurística | Es gratis (4 consultas/min, 500/día), así que quedó **Defender + heurística + VirusTotal** |
| ¿Cómo medir el rendimiento? | En vivo + benchmark | Monitor en tiempo real **y** una prueba antes/después que da un % concreto |

## 3. Verdades incómodas que te dije antes de empezar

- **Un antivirus hecho en casa no detecta virus reales.** La detección real necesita bases de firmas que se actualizan a diario. Por eso el programa usa Windows Defender como motor y le suma heurística propia más VirusTotal.
- **No puedo escanear tu PC desde aquí.** Trabajo en un contenedor Linux en la nube. Construí el programa y lo probé allí; tú lo corres en tu Windows.
- **Borrar "archivos que no usas" es lo más peligroso.** Que un archivo lleve meses sin abrirse no lo convierte en basura. Por eso nada se borra sin tu decisión.

---

## 4. Qué se construyó

**Stack:** motor en Python (con `psutil` como única dependencia) e interfaz HTML/CSS/JS sin librerías externas. La interfaz se abre como ventana de aplicación en Edge.

### Disco (solo reporte)

| Función | Qué hace |
|---|---|
| **Basura** | 19 categorías: Temp de usuario y de Windows, Windows Update, optimización de distribución, `Windows.old`, volcados de errores, informes de errores, miniaturas, logs, instaladores de drivers (NVIDIA/AMD/Intel), cachés de Chrome, Edge, Brave, Opera y Firefox, Discord y Teams, Spotify, pip/npm/yarn, Steam, instaladores viejos en Descargas y la Papelera. Cada una trae **cómo limpiarla** |
| **Grandes sin uso** | Archivos de más de 100 MB sin abrir en más de 180 días (ambos valores configurables). Los clasifica por tipo, incluidos los mods `.scs` de ATS y los `.blend`. Avisa si Windows no registra la fecha de último acceso |
| **Duplicados** | Compara el **contenido**, no el nombre, en 3 fases: tamaño → inicio y final del archivo → hash completo. Omite los archivos de OneDrive que están solo en la nube para no descargarlos |
| **Programas** | Lista los instalados con su tamaño y **último uso** real, que saca de Prefetch y UserAssist. Estados: en uso, poco uso, sin uso y sin registro |

### Seguridad

| Función | Qué hace |
|---|---|
| **Windows Defender** | Muestra si la protección en tiempo real está activa, la edad de las firmas, la protección antialteraciones, el último escaneo, otros antivirus instalados y el historial de amenazas. Botón de **escaneo rápido** |
| **Procesos** | Heurística con puntaje: ejecutables en Temp, Papelera o Descargas, sin firma digital o con firma inválida, nombres que imitan a Windows (`svch0st.exe`), PowerShell con comandos ocultos, descargas con `certutil` o `mshta`, borrado de copias de seguridad (típico de ransomware) y documentos de Office que abren consolas |
| **Arranque** | Revisa las claves Run/RunOnce del registro, la carpeta Inicio y las tareas programadas. Detecta entradas sospechosas y restos de programas desinstalados |
| **VirusTotal** | Confirma los sospechosos con más de 70 antivirus. Solo envía el hash SHA-256, nunca el archivo |

### Rendimiento

| Función | Qué hace |
|---|---|
| **Monitor en vivo** | Gráficas de CPU (con barras por núcleo), RAM, disco y red. Ranking de procesos que separa los de 1.º y 2.º plano, con promedio de 60 s |
| **Benchmark** | Mide CPU multinúcleo, CPU de un núcleo, RAM, escritura en disco y latencia, primero **con todo activo** y luego **con los procesos que elijas en pausa**. Da el **% de rendimiento que te quitan**, con margen de error y cuánto aporta cada proceso. Guarda un historial para comparar antes y después de limpiar |

### Núcleo (pantalla principal)

- Puntaje de **salud de 0 a 100**, con cada descuento explicado (por ejemplo, "-10: Procesos en 2.º plano usan 29% de CPU").
- Botón de **escaneo completo**, que corre 6 módulos seguidos.
- **Exportar reporte** en `.txt`.

### Diseño Matrix

- Lluvia de código (katakana y números) que se intensifica mientras escanea.
- Secuencia de arranque: "Despierta… La Matrix tiene tu disco. Sigue al conejo blanco."
- Logo con efecto glitch, títulos que se "descifran" al cambiar de sección y líneas de escáner tipo monitor CRT.
- Terminal que escribe las líneas en vivo, anillo de salud animado, números que cuentan hacia arriba y alertas que parpadean en rojo.
- Funciona en celular, y si el sistema pide reducir animaciones, las desactiva.

---

## 5. Seguridad del propio programa

| Riesgo | Protección |
|---|---|
| Que una página web use la API local | El servidor solo escucha en `127.0.0.1`, valida el encabezado `Host` y exige un token aleatorio por sesión |
| Que queden procesos congelados después del benchmark | Nunca pausa procesos críticos de Windows ni el navegador de la interfaz. Los reanuda al terminar o cancelar, con el botón **REANUDAR TODO YA**, al cerrar la consola, a los 120 s por un temporizador de seguridad y en el siguiente arranque si el programa se cerró a la fuerza |
| Que el escaneo de duplicados descargue OneDrive completo | Omite los archivos que están solo en la nube |
| Fugas de privacidad | Todo corre local. Lo único que sale a internet son los hashes que tú mandes a VirusTotal |

---

## 6. Qué se probó

| Prueba | Resultado |
|---|---|
| 27 pruebas automáticas (pytest): heurística, duplicados, archivos grandes, programas, configuración, servidor, benchmark | ✅ Todas pasan |
| Pausar y reanudar un proceso real durante el benchmark | ✅ Se pausa en la fase 2 y se reanuda al final |
| Recuperación tras un cierre forzado | ✅ Reanuda el proceso correcto e ignora un PID reutilizado |
| Seguridad del servidor (sin token, host falso, rutas fuera de la carpeta) | ✅ Bloqueado (403/404) |
| Interfaz en Chromium (Playwright): 5 vistas, escaneo completo real, exportar reporte | ✅ 0 errores de JavaScript |
| Celular (390 px de ancho) | ✅ Sin scroll horizontal |
| Lint de Python (pyflakes) y de JavaScript (eslint) | ✅ Sin errores |

**Lo que NO se pudo probar:** nada se ha ejecutado todavía en Windows real. Defender, registro, Prefetch, firmas digitales y pausar procesos de Windows se validaron revisando el código y con pruebas que simulan datos de Windows. **La primera ejecución en tu PC es la prueba de verdad.**

---

## 7. Cómo usarlo en tu PC

1. Instala Python 3.9 o superior: `winget install Python.Python.3.12`.
2. Descarga el código (ver la sección 9).
3. Haz doble clic en **`iniciar.bat`** y acepta el permiso de administrador.
4. La primera vez instala lo necesario solo, y luego se abre la ventana Matrix.
5. **Opcional:** crea tu API key gratis en virustotal.com y pégala en **CONFIG**.

Si algo falla, copia lo que salga en la consola negra y pégamelo.

---

## 8. Archivos del proyecto

```
PC-OPTIMIZATION/
├── iniciar.bat              lanzador de Windows (pide admin, instala, abre)
├── requirements.txt         dependencias (solo psutil)
├── README.md                manual de uso
├── RESUMEN.md               este documento
├── matrixscan/
│   ├── __main__.py          arranque y consola
│   ├── server.py            servidor local + API
│   ├── jobs.py              tareas en segundo plano con progreso
│   ├── disk/                basura, grandes, duplicados, programas
│   ├── security/            heurística, procesos, arranque, firmas, Defender, VirusTotal
│   ├── perf/                monitor en vivo y benchmark
│   └── web/                 interfaz Matrix (HTML, CSS, JS)
└── tests/                   27 pruebas automáticas
```

| Parte | Líneas |
|---|---|
| Motor en Python | ~3.200 |
| Interfaz (HTML/CSS/JS) | ~2.300 |
| Pruebas | ~350 |
| **Total** | **~5.850** |

---

## 9. ¿Qué es un PR (Pull Request)?

Un **PR** (*Pull Request*, "solicitud de integración") es una **propuesta para meter cambios en la versión principal** de tu proyecto en GitHub.

Tu repositorio tiene dos "ramas":

| Rama | Qué tiene |
|---|---|
| `main` (la principal) | Solo el README original. Está prácticamente vacía |
| `claude/sharp-ramanujan-alt5yf` | **Todo MatrixScan** |

El PR #1 dice: *"quiero pasar todo lo de la rama de Claude a `main`"*. Mientras no lo aceptes, `main` sigue vacía. Lo que ves en la barra:

- **`+6,005 −2`**: 6.005 líneas agregadas y 2 borradas (las del README viejo).
- **`○ CI`**: CI (*integración continua*) son pruebas automáticas que GitHub corre en cada cambio. El círculo está vacío porque este repo no tiene ninguna configurada, así que no hay nada en verde ni en rojo.

**El PR no toca tu PC.** Es solo un paso dentro de GitHub. Cuando presionas **Merge** (fusionar), el código pasa a `main`.

**Qué haría yo:** primero probarlo en tu PC descargando el ZIP de la rama. En GitHub: elige la rama `claude/sharp-ramanujan-alt5yf` → **Code** → **Download ZIP**. Si funciona, haces Merge y `main` queda como la versión que sirve. Si algo falla, lo arreglo en la misma rama y el PR se actualiza solo.

---

## 10. Pendientes y próximos pasos

- [ ] Primera ejecución en tu Windows y corrección de lo que salga.
- [ ] Hacer Merge del PR #1 cuando funcione.
- [ ] Opcional: empaquetarlo como un único `.exe` con PyInstaller, para no depender de Python.
- [ ] Opcional: agregar CI para que las pruebas corran solas en GitHub.
