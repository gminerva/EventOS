# Estadísticas (GLOBAL)

La versión actual reporta métricas globales:
- **Total de ventas** y **ingresos** (estados VIGENTE/UTILIZADA)
- **Entradas utilizadas**
- **Precio promedio**
- Series de **ventas por día** (últimos 30 días)
- Agregados por **evento**, **tipo de entrada** y **vendedor**

## Consideraciones
- Se excluyen ventas CANCELADAS de las métricas de ingresos.
- Se utilizan consultas agregadas desde `entradas_vendidas`.
- Las fechas se basan en `fecha_venta` y `fecha_uso`.

## Próximos pasos (futuro)
- Filtro por evento y permisos por rol.
