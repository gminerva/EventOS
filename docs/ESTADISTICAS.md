# Estadísticas: Global vs Por Evento

- Global (solo Admin):
  Muestra KPIs totales, series de ventas y agregados en toda la plataforma.

- Por Evento (Staff/Admin):
  Filtra métricas por `evento_id`.
  Ejemplos de KPIs: entradas vendidas, utilizadas, ingresos, promedio de precio.

# Permisos
- Admin: puede ver GLOBAL y cualquier evento.
- Staff: solo puede ver eventos a cargo o asignados.

# Notas de diseño
- Todas las consultas usan `estado IN ("VIGENTE","UTILIZADA")` para ingresos/ventas vigentes.
- Entradas expiran automáticamente si el evento ya pasó.
