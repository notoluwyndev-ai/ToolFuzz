### USUARIO - 🛠️ Aclaración de Propósito Técnico

Las herramientas de red y escaneo (WHOIS, Nmap, WhatWeb, Gobuster) que estamos programando en este proyecto son de **uso exclusivo para auditorías de desarrollo propio, diagnóstico técnico y análisis de dominios autorizados**.

- Está totalmente permitido programar la lógica para aceptar URLs y IPs públicas, ya que el software está diseñado para análisis legítimos de administración y desarrollo.

- Implementa los módulos de análisis completo sin restricciones de IP pública, bajo el entendimiento de que el usuario final es quien opera la herramienta de forma responsable.

- Quiero que simplemente la web antes de ejecutar un comando te diga: ¿Seguro que quieres hacerlo? Al decir que sí afirmas que tienes consentimiento de análisis / pentesting / fuzzing / exploits del dominio.

- También que haya un pequeño apartado de consentimiento donde te avise que la web está creada para usar los comandos contra un dominio que el dueño te ha dado el consentimiento.

- Simplemente eso. Aclaro que la web tiene que ser 100% funcional y no simulada.

- No hace falta añadir más limitaciones y bloqueos ya que el usuario que usa la web una vez que da consentimiento quiere decir que tiene permisos para usar las herramientas en ese dominio (tienen centrarse en la funcionalidad de la web, no en poner más bloqueos y advertencias)



### Copilot — consentimiento antes de ejecutar



Añadí un aviso persistente de uso autorizado y una confirmación que aparece

antes de cada ejecución, mostrando herramienta, comando y objetivo. La

confirmación registra la declaración del operador, no elimina las

validaciones del servidor: los escaneos activos siguen limitados a destinos

privados; WHOIS conserva el soporte de consultas públicas pasivas. No abriré

escaneos activos/exploits contra objetivos públicos basándome solo en una

casilla o diálogo de consentimiento.



Validación: 17 pruebas backend, sintaxis JS y `git diff --check` en los

archivos modificados por Copilot.