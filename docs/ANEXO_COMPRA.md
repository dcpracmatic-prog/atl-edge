# ATL Edge — anexo de compra

Dos páginas. Qué hace, qué no hace, y cómo verificarlo sin creernos nada.

Versión: piloto sobre `v0.1.0-mvp` · SmartTokenProd `v0.10.4`

---

## 1. Qué hace

**El problema.** Para que un agente sea útil necesita datos. La integración
normal le entrega una credencial de base y confía en que el prompt aguante. La
fila entera queda al alcance del modelo, y lo que salió no queda probado.

**Lo que hace ATL.** Un nodo local decide qué campos salen, emite un paquete
sellado con exactamente esos campos, y deja constancia. El resto de la fila no
se mueve del nodo.

```
agente / MCP host  --propone-->  nodo ATL  -->  sus datos (local)
                   <--paquete sellado--
```

### Las cinco cosas concretas

| | |
|---|---|
| **Propuesta acotada** | El operador pide en lenguaje natural acotado. Un intérprete de plantilla produce una propuesta con esquema válido, o se niega. No hay paso de prosa a consulta libre. |
| **Compuerta de campos** | Un catálogo declara recursos, campos y sensibilidad. Una política de nodo declara qué puede ver ese nodo. Lo pedido fuera de eso se rechaza con motivo. |
| **Sello con campos** | Sin `fields` no hay sello. El paquete contiene la proyección, no la fila. |
| **Apertura con clave de nodo** | El conector abre el paquete con la clave derivada del nodo, nunca con la clave maestra de provisión. |
| **Recibo** | Decisión, campos emitidos, campos retenidos, bytes retenidos contra bytes del registro, TTL, `request_id`, política. Visible en consola y en transcript. |

### Prueba medida, no folleto

Sobre datos reales (UCI Online Retail, CC BY 4.0), el nodo sirviendo un catálogo
de inventario:

| Solicitud | Resultado |
|---|---|
| `sku, description, qty_on_hand` | Aceptada. Sale eso. **81.0% del registro no salió**. `unit_price_gbp` y `distinct_customers` ausentes del texto claro. |
| `sku, qty, moved_at` sobre movimientos | Aceptada. **88.8% no salió**. `customer_id`, `invoice_no`, `country` ausentes — ni sus **valores** aparecen. |
| "dame todo" | Rechazada. `403`. Sin paquete. |
| `customer_id` directo | Rechazada, `field_not_allowed`. |
| Precios | Rechazada, `field_not_allowed`. |
| Petición destructiva | Rechazada **en el proponente**, antes de leer nada. |
| Sin campos declarados | Rechazada. Sin campos no hay sello. |

Reproducible: `python examples/inventory_trade_demo.py`.

### El agente nativo

Se vende como **intérprete acotado incluido**. Eso es lo que hay: una plantilla
determinista que produce propuestas válidas o se niega. **La garantía es la
plantilla.**

El modelo local es **opcional y todavía no verificado en vivo** — la
decodificación restringida contra un GGUF está configurada y probada a nivel de
configuración, pero `llama-cpp-python` no compiló en el entorno de trabajo, así
que no hay una corrida en vivo que mostrarle. Toda la evidencia calificada de
este anexo corre sobre la plantilla, y un job de CI lo verifica. El cargador
falla cerrado y nunca descarga un modelo por su cuenta.

No se vende como "LLM gratuito milagroso". Si alguien se lo presentó así, estaba
vendiendo otra cosa.

---

## 2. Qué **no** hace

Esta lista existe para que no compre lo que no es. Cada línea es una limitación
real, no un "aún no".

| No hace | Qué significa para usted |
|---|---|
| **No SSO** | No hay SAML ni OIDC. La consola se autentica con un token de operador local. Si necesita identidad corporativa, va delante, no dentro. |
| **No HSM** | Las claves viven en archivos con permisos del sistema. SQLite de referencia, no KMS ni Postgres. Suficiente para un piloto; no es custodia de nivel banco. |
| **No llama a modelos premium** | El nodo **no inicia** llamadas a APIs de modelos de pago ni de agentes. No es una omisión: hay un invariante escrito, red-team que rechaza `premium`/`http`/`openai`/`shell`, y CI que falla si aparece un cliente de proveedor en el plano de datos. El nodo no es cliente de un LLM premium. |
| **No es IAM de su base** | Gobierna lo que sale **por esta frontera**. Quien tenga credenciales directas a la base las sigue teniendo. ATL no revoca ese acceso. |
| **No es multiplataforma todavía** | Un oficio funciona de punta a punta (inventario). Un conector pasivo (MCP genérico). La amplitud viene después, no en lugar de. |
| **No es chat contra su base** | El conector expone tres herramientas: `propose`, `execute`, `open_package`. No hay `query`, `sql`, `search` ni `chat`, y un guardián de CI falla si la lista crece. |
| **La consola no emite licencias** | Separación deliberada. La consola opera; el plano de control licencia. |
| **No expone nada a la red por defecto** | Loopback (`:8790` / `:8795`). Exponerlo requiere proxy TLS suyo. El conector rechaza arrancar apuntado a un host remoto. |
| **El modelo local no está verificado en vivo** | Repetido aquí a propósito. Ver arriba. |

### Reducción de bytes: cómo leerla

Los porcentajes de arriba son **la parte del registro que no salió**, medida
sobre esas solicitudes. No es una constante del producto: depende de qué tan
ancha es su fila y qué tan poco pide el agente.

Aparte, el paquete sellado es **más grande** que un registro chico (sobre,
encabezado, etiqueta AEAD: +184% para una fila de dos campos). La minimización
es de **campos**, no de tamaño en el cable. Si alguien le vende ahorro de banda,
no es esto.

---

## 3. Qué se instala

- `start_stack.sh` — Edge y consola en loopback, una orden.
- Imagen Docker equivalente (`docker/`), probada en CI.
- **Licencia de nodo**, no de token: un entitlement firmado Ed25519 y ligado a
  un `node_id`.

La licencia ligada a un nodo es **rechazada en otro nodo**, y un entitlement
emitido sin `node_id` — que la capa criptográfica sola aceptaría en cualquier
nodo — es **rechazado por el Edge**. Sin eso, `max_nodes=1` sería decoración.
Verificable: `python testbench/node_licence_selftest.py`.

---

## 4. Cómo lo verifica usted

Sin creernos nada, en su máquina:

```bash
bash scripts/validate_all.sh                              # 11 etapas
python testbench/run_testbench.py --require-full          # batería adversarial
python testbench/red_team_bypass_v1.py --require-clean    # red-team
python testbench/node_licence_selftest.py                 # licencia de nodo
python testbench/console_governance_selftest.py           # el recibo visible
python scripts/check_egress_invariant.py --self-test      # el nodo no llama afuera
python scripts/check_mcp_surface.py --self-test           # tres herramientas
ATL_CATALOG=inventory bash scripts/start_stack.sh
python examples/inventory_trade_demo.py                   # la prueba sobre datos reales
python examples/mcp_connector_demo.py                     # el conector, en vivo
```

Los guardianes traen `--self-test`: se inyectan la violación que deben detectar
y fallan si el guardián dejó de morder. Un guardián que dejó de funcionar no
puede seguir reportando verde.

CI en `main` corre todo lo anterior en cada cambio.

### Limitaciones conocidas que le declaramos

1. El modelo local no está verificado en vivo (ver §1).
2. Una aserción de fuga por substring solo aplica a valores de 4+ caracteres:
   valores de un dígito aparecen por coincidencia dentro de otros campos. La
   aserción de **ausencia de campo** no tiene esa limitación.
3. El red-team reporta un hallazgo conocido de confianza dentro del proceso
   (RT1): quien ya ejecuta código en el nodo no está en el modelo de amenaza.
4. Sin datos suyos, esto sigue siendo una demostración sobre un dataset público.
   El siguiente paso real es su catálogo.

---

## Fuentes

- Dataset: Chen, D. (2015). *Online Retail*. UCI Machine Learning Repository, CC BY 4.0 — https://doi.org/10.24432/C5BW33 · https://archive.ics.uci.edu/dataset/352/online+retail
- Documentos internos: `iva.md` (invariante y amenazas), `docs/THREAT_MODEL.md`, `docs/MCP_CONNECTOR.md`, `docs/CONSOLE.md`, `docs/licensing-production.md`
