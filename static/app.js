/* CiberTriage - lógica del cliente. Los tokens viven solo en memoria (no en localStorage). */
(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  let sesion = null; // {access, refresh, nombre}

  const el = (tag, props = {}, ...hijos) => {
    const e = document.createElement(tag);
    Object.assign(e, props);
    hijos.flat().forEach((h) => e.append(h));
    return e;
  };
  const fmt = (iso) => new Date(iso).toLocaleString('es-AR');
  const alerta = (cont, clase, texto) => {
    cont.replaceChildren(el('div', { className: `alert alert-${clase}`, textContent: texto }));
  };

  async function api(ruta, opciones = {}, reintento = true) {
    const cab = new Headers(opciones.headers || {});
    if (sesion) cab.set('Authorization', `Bearer ${sesion.access}`);
    const r = await fetch(ruta, { ...opciones, headers: cab });
    if (r.status === 401 && sesion && reintento && (await renovar())) return api(ruta, opciones, false);
    if (r.status === 401 && sesion) cerrarLocal('Su sesión venció. Ingrese nuevamente.');
    return r;
  }
  async function detalleError(r) {
    try { const d = await r.json(); return typeof d.detail === 'string' ? d.detail : 'Datos inválidos'; }
    catch { return `Error ${r.status}`; }
  }
  async function renovar() {
    try {
      const r = await fetch('/api/auth/refresh', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: sesion.refresh }),
      });
      if (!r.ok) return false;
      const d = await r.json();
      sesion.access = d.access_token; sesion.refresh = d.refresh_token;
      return true;
    } catch { return false; }
  }

  // ---------- Ventana 1: consulta pública de IoC ----------
  $('form-consulta').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const cont = $('resultado-consulta');
    const r = await fetch('/api/consulta-ioc', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tipo: $('search-tipo').value, valor: $('search-valor').value }),
    });
    if (!r.ok) return alerta(cont, 'warning', await detalleError(r));
    const d = await r.json();
    alerta(cont, d.coincidencias ? 'danger' : 'success', d.mensaje);
  });

  // ---------- Ventana 2: envío de reporte ----------
  $('form-denuncia').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const form = ev.target;
    const boton = form.querySelector('button[type="submit"]');
    let cont = $('resultado-denuncia');
    if (!cont) { cont = el('div', { id: 'resultado-denuncia', className: 'mt-3' }); form.append(cont); }
    if (boton) boton.disabled = true;
    try {
      const r = await fetch('/api/reportes', { method: 'POST', body: new FormData(form) });
      if (!r.ok) return alerta(cont, 'danger', await detalleError(r));
      const d = await r.json();
      const caja = el('div', { className: 'alert alert-success' },
        el('strong', { textContent: `Reporte recibido. Número de ticket: ${d.ticket}` }),
        el('div', { className: 'small mt-1', textContent: 'Conserve este número. Puede guardar también las huellas SHA-256 de sus archivos:' }));
      if (d.evidencias.length) {
        caja.append(el('ul', { className: 'small mb-0' },
          d.evidencias.map((e) => el('li', {}, `${e.nombre}: `, el('code', { textContent: e.sha256 })))));
      }
      cont.replaceChildren(caja);
      form.reset();
    } catch {
      alerta(cont, 'danger', 'No se pudo conectar con el servidor.');
    } finally {
      if (boton) boton.disabled = false;
    }
  });

  // ---------- Ventana 3: personal autorizado ----------
  function cerrarLocal(mensaje) {
    sesion = null;
    $('panel-triage-container').classList.add('d-none');
    $('login-policial-container').classList.remove('d-none');
    $('tabla-reportes-pendientes').replaceChildren();
    $('password-policial').value = '';
    if (mensaje) { $('login-error').textContent = mensaje; $('login-error').classList.remove('d-none'); }
  }

  $('form-login-policial').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const err = $('login-error'); err.classList.add('d-none');
    const r = await fetch('/api/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usuario: $('usuario-policial').value, password: $('password-policial').value }),
    });
    if (!r.ok) { err.textContent = await detalleError(r); err.classList.remove('d-none'); return; }
    const d = await r.json();
    sesion = { access: d.access_token, refresh: d.refresh_token, nombre: d.usuario };
    $('password-policial').value = '';
    $('nombre-sesion').textContent = d.usuario;
    $('login-policial-container').classList.add('d-none');
    $('panel-triage-container').classList.remove('d-none');
    cargarReportes();
  });

  $('btn-cerrar-sesion').addEventListener('click', async () => {
    try { await api('/api/auth/logout', { method: 'POST' }, false); } catch { /* sin conexión */ }
    cerrarLocal();
  });

  const ESTADO = { pendiente: 'warning text-dark', aprobado: 'success', desestimado: 'secondary' };

  async function cargarReportes() {
    const r = await api('/api/reportes');
    if (!r.ok) return;
    const filas = await r.json();
    const tbody = $('tabla-reportes-pendientes');
    if (!filas.length) {
      tbody.replaceChildren(el('tr', {}, el('td', { colSpan: 7, className: 'text-center text-muted', textContent: 'Sin reportes registrados.' })));
      return;
    }
    tbody.replaceChildren(...filas.map((f) => {
      const accion = (texto, clase, fn) => {
        const b = el('button', { type: 'button', className: `btn btn-sm ${clase} fw-bold me-1`, textContent: texto });
        b.addEventListener('click', fn); return b;
      };
      return el('tr', {},
        el('td', {}, el('code', { textContent: f.ticket })),
        el('td', { textContent: fmt(f.fecha) }),
        el('td', { textContent: f.tipologia }),
        el('td', { textContent: f.indicadores }),
        el('td', { textContent: f.evidencias }),
        el('td', {}, el('span', { className: `badge bg-${ESTADO[f.estado] || 'secondary'}`, textContent: f.estado })),
        el('td', { className: 'text-center' },
          accion('Ver detalle', 'btn-info text-white', () => verDetalle(f.id)),
          accion('Aprobar', 'btn-success', () => cambiarEstado(f.id, 'aprobado')),
          accion('Desestimar', 'btn-danger', () => cambiarEstado(f.id, 'desestimado'))));
    }));
  }

  async function cambiarEstado(id, estado) {
    const r = await api(`/api/reportes/${id}/estado`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ estado }),
    });
    if (r.ok) cargarReportes();
  }

  async function descargar(ev, e) {
    ev.preventDefault();
    const r = await api(`/api/evidencias/${e.id}/descargar`);
    if (!r.ok) return window.alert(await detalleError(r));
    const url = URL.createObjectURL(await r.blob());
    const a = el('a', { href: url, download: e.nombre });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function verDetalle(id) {
    const r = await api(`/api/reportes/${id}`);
    if (!r.ok) return;
    const d = await r.json();
    $('det-ticket').textContent = d.ticket;
    $('det-fecha').textContent = fmt(d.fecha);
    $('det-tipologia').textContent = d.tipologia;
    const p = d.denunciante;
    $('det-denunciante').textContent = [p.nombre_apellido, p.cuil_dni, p.telefono, p.email].filter(Boolean).join(' · ');
    $('det-ioc').textContent = d.indicadores.map((i) => `${i.tipo}: ${i.valor}`).join(' | ') || 'Sin indicadores';
    $('det-hash').replaceChildren(...(d.evidencias.length ? d.evidencias.map((e) => {
      const enlace = el('a', { href: '#', textContent: e.nombre });
      enlace.addEventListener('click', (ev) => descargar(ev, e));
      return el('li', {}, enlace, ` (${e.mime}, ${e.tamano} B) `, el('code', { textContent: e.sha256 }));
    }) : [el('li', { textContent: 'Sin evidencias adjuntas' })]));
    $('det-relato').textContent = d.relato;
    bootstrap.Modal.getOrCreateInstance($('modalDetalleReporte')).show();
  }
})();
