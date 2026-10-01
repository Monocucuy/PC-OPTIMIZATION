# MATRIX//SCAN

Analizador local para **Windows 10/11** con interfaz estilo Matrix: lluvia de código, terminal animada y gráficas en vivo.

- **Disco:** basura del sistema, archivos grandes que no usas, duplicados y programas abandonados.
- **Seguridad:** Windows Defender, heurística de procesos y arranque, y confirmación con VirusTotal.
- **Rendimiento:** consumo en vivo de los procesos en segundo plano, y un benchmark que mide **cuánto rendimiento te quitan**.

> **Solo lectura.** MatrixScan no borra ni modifica archivos. Te dice qué hay, cuánto pesa y cómo limpiarlo a mano.
> Solo actúa sobre el sistema en el benchmark: pausa de forma temporal los procesos que tú marques y los reanuda siempre.

## Uso

1. Instala **Python 3.9 o superior**. La forma más rápida es `winget install Python.Python.3.12`.
2. Haz doble clic en **`iniciar.bat`** y acepta el permiso de administrador.
   - La primera vez crea `.venv` e instala `psutil`, la única dependencia.
   - Si rechazas el permiso, el programa funciona igual, pero con análisis parcial.
3. La interfaz se abre como ventana de aplicación (Edge en modo app).
4. Para cerrar MatrixScan, cierra la consola negra.

Sin el lanzador: `python -m pip install -r requirements.txt` y luego `python -m matrixscan`.

## Módulos

| Sección | Qué analiza | De dónde saca los datos |
|---|---|---|
| **Disco → Basura** | Temp, Windows Update, optimización de distribución, `Windows.old`, volcados, informes de errores, miniaturas, logs, instaladores de drivers, cachés de Chrome, Edge, Brave, Opera y Firefox, Discord, Teams, Spotify, pip, npm, Steam, instaladores viejos en Descargas y la Papelera | Tamaño real de cada carpeta. Cada categoría trae **cómo limpiarla** |
| **Disco → Grandes sin uso** | Archivos de más de N MB sin abrir en más de N días, por tipo (video, ISO, comprimido, mods `.scs`, `.blend`…) | Fecha de último acceso o modificación |
| **Disco → Duplicados** | Archivos idénticos **por contenido** | Tamaño → hash parcial → hash BLAKE2 completo |
| **Disco → Programas** | Instalados, tamaño y **último uso** | Registro de desinstalación + Prefetch + UserAssist |
| **Seguridad → Defender** | Tiempo real, firmas, antialteraciones, último escaneo, otros antivirus, historial de detecciones y **escaneo rápido** | `Get-MpComputerStatus`, `MpCmdRun.exe`, SecurityCenter2 |
| **Seguridad → Procesos** | Señales de malware: ejecutables en Temp, Papelera o Descargas, sin firma o con firma inválida, nombres que imitan a Windows (`svch0st.exe`), PowerShell codificado, descargas con `certutil` o `mshta`, borrado de copias de seguridad (ransomware), Office lanzando consolas | psutil + firma Authenticode |
| **Seguridad → Arranque** | Claves Run/RunOnce, carpetas de Inicio y tareas programadas: las sospechosas y los restos de programas desinstalados | Registro + `Get-ScheduledTask` |
| **Seguridad → VirusTotal** | Confirma los sospechosos con más de 70 antivirus | API v3 (solo se envía el SHA-256) |
| **Rendimiento** | CPU, RAM, disco y red en vivo; ranking de procesos en 1.º y 2.º plano con promedio de 60 s | psutil + ventanas visibles (Win32) |
| **Rendimiento → Benchmark** | Mide CPU (multi y un núcleo), RAM y disco (escritura y latencia) **con todo activo** y **con los procesos elegidos en pausa**. La diferencia es el % que te quitan | Pruebas propias, 3 repeticiones con mediana y margen de error |
| **Núcleo** | Puntaje de salud 0–100 con cada descuento explicado, escaneo completo en un clic y reporte `.txt` exportable | Todo lo anterior |

## VirusTotal (gratis)

1. Crea una cuenta en <https://www.virustotal.com/gui/join-us>.
2. Copia la **API key** desde tu perfil.
3. Pégala en **CONFIG** dentro de MatrixScan.

Límite gratuito: 4 consultas por minuto y 500 al día (uso personal). MatrixScan espacia las consultas y guarda los resultados en caché durante 7 días.

## Límites

- **No es un antivirus.** La heurística marca comportamientos raros, no virus confirmados. Para confirmar, usa Defender y VirusTotal desde la misma pantalla. Un "riesgo alto" significa que vale la pena revisarlo, no que sea un virus.
- **Último uso de archivos:** en muchos equipos Windows desactiva el registro de último acceso. MatrixScan lo detecta y te avisa, porque en ese caso un archivo pudo abrirse más recientemente de lo que dice el reporte.
- **Programas "sin registro":** Prefetch guarda unos 1024 ejecutables. Que un programa no aparezca allí es una pista fuerte, pero no una prueba. Prefetch necesita permisos de administrador.
- **Benchmark:** los resultados varían entre corridas por turbo boost y temperatura. Por eso se muestra el margen de error, y las diferencias menores a ese margen se marcan con `~`.
- **Pausar procesos:** nunca se pausan procesos críticos de Windows ni el navegador que muestra la interfaz. Los procesos pausados se reanudan:
  - al terminar o cancelar el benchmark;
  - con el botón **REANUDAR TODO YA**;
  - al cerrar la consola;
  - a los 120 s por un temporizador de seguridad;
  - en el siguiente arranque, si MatrixScan se cerró a la fuerza.

## Privacidad y seguridad

- Todo corre en tu PC. El servidor escucha solo en `127.0.0.1`, valida el encabezado `Host` y exige un token aleatorio por sesión. Así, ninguna página web puede usar la API.
- Lo único que sale a internet son los hashes SHA-256 que tú mandes a VirusTotal.
- La configuración, la caché de VirusTotal y el historial del benchmark se guardan en `%APPDATA%\MatrixScan\`.

## Desarrollo

```
matrixscan/
  __main__.py        arranque, consola y ventana
  server.py          servidor HTTP local + API JSON
  jobs.py            trabajos en segundo plano (progreso, log, cancelar)
  disk/              junk, large_files, duplicates, programs
  security/          heuristics, processes, persistence, signatures, defender, virustotal
  perf/              monitor (en vivo), benchmark (pausa segura)
  web/               interfaz HTML/CSS/JS sin dependencias externas
tests/               pytest
```

```bash
pip install psutil pytest
python -m pytest
```

Las funciones exclusivas de Windows (registro, Defender, Prefetch, firmas) degradan sin error en Linux y macOS, así que la interfaz y las pruebas corren en cualquier sistema.
