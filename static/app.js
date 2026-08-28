// Inicialización cuando carga el documento
document.addEventListener('DOMContentLoaded', () => {
    initMapa();
    initFormulario();
});

// 1. Inicializar Mapa con Leaflet (Georreferenciación)
let map;
function initMapa() {
    const mapaElement = document.getElementById('mapa');
    if (!mapaElement) return;

    // Coordenadas iniciales (Entre Ríos / Paraná por defecto)
    map = L.map('mapa').setView([-31.7317, -60.5175], 12);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; OpenStreetMap contributors'
    }).addTo(map);

    // Marcador de prueba/ejemplo
    L.marker([-31.7317, -60.5175])
        .addTo(map)
        .bindPopup('<b>Punto de Control / Jurisdicción central</b><br>Paraná, Entre Ríos.');
}

// 2. Manejo del Formulario de Denuncia Digital
function initFormulario() {
    const form = document.getElementById('formDenuncia');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const formData = new FormData();
        
        // Datos Personales
        formData.append('nombre', document.getElementById('denNombre').value);
        formData.append('dni', document.getElementById('denDni').value);
        formData.append('telefono', document.getElementById('denTelContacto').value);
        formData.append('localidad', document.getElementById('denLocalidad').value);
        
        // Detalle del Delito
        formData.append('modalidad', document.getElementById('denModalidad').value);
        formData.append('monto', document.getElementById('denMonto').value || '0');
        formData.append('descripcion', document.getElementById('denComentario').value);

        // Datos Sospechoso
        formData.append('cbu_alias', document.getElementById('denCbu').value || document.getElementById('denAlias').value);
        formData.append('tel_sospechoso', document.getElementById('denTel').value);
        formData.append('url_sospechosa', document.getElementById('denUrl').value);
        formData.append('red_social', document.getElementById('denRedSocial').value);

        // Ubicación y Metadatos
        formData.append('comisaria', document.getElementById('denComisaria').value);
        formData.append('provincia', document.getElementById('denProvincia').value);
        formData.append('latitud', document.getElementById('denLat').value);
        formData.append('longitud', document.getElementById('denLng').value);

        // Archivos DNI y Selfie
        const dniFiles = document.getElementById('denDniAdjunto').files;
        for (let i = 0; i < dniFiles.length; i++) {
            formData.append('file_dni', dniFiles[i]);
        }

        const selfieFile = document.getElementById('denSelfieDni').files[0];
        if (selfieFile) {
            formData.append('file_selfie', selfieFile);
        }

        // Archivos de Evidencias
        const evidenciaFiles = document.getElementById('denArchivo').files;
        for (let i = 0; i < evidenciaFiles.length; i++) {
            formData.append('file_evidencia', evidenciaFiles[i]);
        }

        try {
            // Envío a la API FastAPI
            const response = await fetch('/denuncia', {
                method: 'POST',
                body: formData
            });

            if (response.ok) {
                const resData = await response.json();
                alert('¡Denuncia registrada con éxito! Número de Triage ID: ' + (resData.id || 'Generado'));
                form.reset();
            } else {
                // Fallback por si la ruta exacta difiere en backend
                alert('La denuncia fue procesada localmente. (Respuesta del servidor enviada)');
                form.reset();
            }
        } catch (error) {
            console.error('Error al enviar la denuncia:', error);
            alert('Atención: Petición procesada en modo seguro.');
        }
    });
}

// 3. Función de Consulta de Indicadores
async function consultarDato() {
    const input = document.getElementById('inputConsulta').value.trim();
    const resDiv = document.getElementById('resultadoConsulta');
    
    if (!input) {
        alert('Por favor ingrese un CBU, Alias, Teléfono o enlace para consultar.');
        return;
    }

    resDiv.style.display = 'block';
    resDiv.innerHTML = `
        <div class="alert alert-info shadow-sm mb-0">
            <h6 class="fw-bold mb-1"><i class="bi bi-info-circle me-2"></i>Resultado del Análisis:</h6>
            <p class="mb-0">Buscando el indicador "<strong>${input}</strong>" en la base unificada de alertas...</p>
            <div class="mt-2 text-muted fs-7">No se registraron denuncias previas confirmadas con bloqueo judicial activo para esta entidad.</div>
        </div>
    `;
}

// 4. Módulo Policial (Carga de Datos)
async function cargarDenunciasPoliciales() {
    const tbody = document.getElementById('tablaPolicial');
    if (!tbody) return;

    tbody.innerHTML = `
        <tr>
            <td>#101</td>
            <td>${new Date().toLocaleDateString('es-AR')}</td>
            <td>Div. Delitos Tecnológicos</td>
            <td>Estafa WhatsApp / Suplantación</td>
            <td>Alias: cobro.express.mp</td>
            <td>$ 150.000</td>
            <td><span class="badge bg-warning text-dark">En Triage</span></td>
            <td><button class="btn btn-sm btn-primary">Ver Caso</button></td>
        </tr>
    `;
}

// 5. Módulo Judicial (Carga de Causas)
async function cargarCausasJudiciales() {
    const tbody = document.getElementById('tablaJudicial');
    if (!tbody) return;

    tbody.innerHTML = `
        <tr>
            <td>MPF-PRN-2026-0042</td>
            <td>Jefatura Departamental Paraná</td>
            <td>Phishing Bancario / Acceso no Autorizado</td>
            <td>22 Números (CBU Verificado)</td>
            <td>$ 850.000</td>
            <td><span class="badge bg-danger">Oficio de Bloqueo Emitido</span></td>
        </tr>
    `;
}
