# UDP Flooder

**UDP Flooder** es una herramienta de prueba diseñada para realizar ataques de Denegación de Servicio (DoS) utilizando paquetes UDP. Este script puede ser usado para evaluar la capacidad de resistencia de sistemas de red al enviar grandes volúmenes de tráfico UDP a una IP objetivo.

## Descripción

El script genera y envía paquetes UDP a un puerto específico de una IP objetivo para simular un ataque de flood. Utiliza múltiples hilos para enviar tráfico de manera simultánea, lo que permite simular ataques distribuidos de forma más realista. Puedes configurar el número de hilos, el puerto de destino y el archivo de IPs objetivo para personalizar el ataque.

## Características

- **Envío de paquetes UDP**: Crea y envía paquetes UDP con encabezados IP y UDP manipulados.
- **Soporte para múltiples hilos**: Ejecuta el ataque usando varios hilos para generar mayor tráfico.
- **Configuración dinámica**: Ajusta parámetros como puerto de destino, duración del ataque y puerto UDP.
- **Lectura desde archivo**: Carga múltiples IPs objetivo desde un archivo de texto para realizar el ataque.

## Requisitos

- **Sistema operativo**: Linux (Ubuntu recomendado)
- **Compilador**: GCC (`gcc`)
## Instrucciones de Uso
### Compilación
Compila el script usando el siguiente comando:
```bash
gcc -o udp_flooder udp_flooder.c -lpthread
```
### Ejecución
Ejecuta el script con el siguiente comando:
```bash
./udpflood <IP_destino> <puerto_UDP_destino> <número_de_hilos> <duración> <archivo_ips>
```
### **Advertencias**

1. **Aviso Legal**: Esta herramienta está destinada a fines educativos y pruebas de seguridad en redes en un entorno controlado. El uso no autorizado contra sistemas o redes que no poseas o para los cuales no tengas permiso explícito para probar es ilegal y poco ético.

2. **Uso Ético**: Siempre obtén la autorización adecuada antes de usar esta herramienta. El uso indebido de esta herramienta puede causar daño, pérdida de datos o consecuencias legales.

3. **Riesgo de Uso Inadecuado**: Al usar este script, reconoces que eres completamente responsable de cualquier consecuencia derivada de su uso. Los autores y mantenedores de este repositorio no se hacen responsables de daños o problemas legales resultantes de su uso.

4. **Impacto en la Red**: Ten en cuenta que el uso de esta herramienta puede interrumpir los servicios de red y afectar a otros usuarios. Solo debe usarse en un entorno controlado e aislado.

5. **Cumplimiento**: Asegúrate de cumplir con todas las leyes y regulaciones relevantes en tu jurisdicción al usar esta herramienta.

